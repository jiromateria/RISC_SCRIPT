import math
import json
import sys
from dataclasses import dataclass, field


@dataclass
class Field:
    name: str
    length: int = -1
    lsb: int | None = None
    msb: int | None = None
    is_fixed: bool = False
    is_variable: bool = False
    min_length: int | None = None
    degree: int = 0


@dataclass
class Command:
    name: str
    opcode: int | None = None


@dataclass
class Format:
    name: str
    commands: list = field(default_factory=list)
    operands: list = field(default_factory=list)
    code: int | None = None


def parse_field(raw):
    name, val = list(raw.items())[0]
    if isinstance(val, str) and val.startswith(">="):
        return Field(name, is_variable=True, min_length=int(val[2:]))
    return Field(name, length=int(val), is_fixed=True)


def load_data(data):
    fields = [parse_field(f) for f in data["fields"]]

    formats = {}
    for ins in data["instructions"]:
        name = ins["format"]

        if name not in formats:
            formats[name] = Format(name=name, operands=list(ins["operands"]))

        for c in ins["insns"]:
            formats[name].commands.append(Command(c))

    return fields, list(formats.values()), int(data["length"])


def add_opcode(fields, formats):
    max_cmds = max(len(f.commands) for f in formats)
    if max_cmds <= 1:
        return None

    size = math.ceil(math.log2(max_cmds))
    op = Field("OPCODE", length=size, is_fixed=True)
    fields.append(op)

    for f in formats:
        if len(f.commands) > 1:
            f.operands.append("OPCODE")

    return op


def build_conflicts(fields, formats):
    index = {f.name: i for i, f in enumerate(fields)}
    n = len(fields)
    m = [[0] * n for _ in range(n)]

    for fmt in formats:
        ids = [index[o] for o in fmt.operands if o in index]
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = ids[i], ids[j]
                m[a][b] = m[b][a] = 1

    for f in fields:
        f.degree = sum(m[index[f.name]])

    return m, index


class Layout:
    def __init__(self, size, index, matrix):
        self.size = size
        self.bits = [set() for _ in range(size)]
        self.index = index
        self.matrix = matrix
        self.placed = {}

    def can_place(self, name, lsb, length):
        msb = lsb + length - 1
        if msb >= self.size or lsb < 0:
            return False

        fid = self.index.get(name)

        for i in range(lsb, msb + 1):
            for occ in self.bits[i]:
                if occ == name:
                    continue
                if occ == "F":
                    return False
                oid = self.index.get(occ)
                if fid is not None and oid is not None:
                    if self.matrix[fid][oid]:
                        return False
        return True

    def clear(self, name):
        for b in self.bits:
            b.discard(name)

    def place(self, field, lsb, length):
        self.clear(field.name)
        msb = lsb + length - 1

        for i in range(lsb, msb + 1):
            self.bits[i].add(field.name)

        field.lsb, field.msb = lsb, msb
        self.placed[field.name] = field

    def find_spot(self, name, length, reverse=False):
        rng = range(self.size - length, -1, -1) if reverse else range(self.size - length + 1)
        for pos in rng:
            if self.can_place(name, pos, length):
                return pos
        return None


def place_F(layout, formats):
    size = math.ceil(math.log2(len(formats)))
    f = Field("F", length=size, is_fixed=True)
    layout.place(f, layout.size - size, size)

    for i, fmt in enumerate(formats):
        fmt.code = i

    return f


def place_fields(fields, layout, opcode):
    order = [f for f in fields if f.name not in ("F", "OPCODE")]
    order.sort(key=lambda f: (
        not f.is_fixed,
        -f.degree,
        -(f.length if f.is_fixed else f.min_length),
        f.name
    ))

    if opcode:
        order.insert(0, opcode)

    for f in order:
        size = f.length if f.is_fixed else f.min_length
        pos = layout.find_spot(f.name, size, f.is_fixed)
        if pos is None:
            raise RuntimeError(f"cannot place {f.name}")
        layout.place(f, pos, size)


def expand_vars(layout, fields):
    for f in fields:
        if not f.is_variable or f.name not in layout.placed:
            continue

        while True:
            cur = layout.placed[f.name]
            l, r = cur.lsb, cur.msb

            if l > 0 and layout.can_place(f.name, l - 1, r - l + 2):
                layout.place(f, l - 1, r - l + 2)
            elif r < layout.size - 1 and layout.can_place(f.name, l, r - l + 2):
                layout.place(f, l, r - l + 2)
            else:
                break


def build_output(formats, layout):
    res_map = {}
    res_id = 0
    out = []

    for fmt in formats:
        f_bits = format(fmt.code, f'0{layout.placed["F"].length}b')

        for i, cmd in enumerate(fmt.commands):
            entry = {"insn": cmd.name, "fields": []}

            f = layout.placed["F"]
            entry["fields"].append({"F": {"msb": f.msb, "lsb": f.lsb, "value": f_bits}})

            if "OPCODE" in layout.placed and "OPCODE" in fmt.operands:
                op = layout.placed["OPCODE"]
                val = format(i, f'0{op.length}b')
                entry["fields"].append({"OPCODE": {"msb": op.msb, "lsb": op.lsb, "value": val}})

            for name in fmt.operands:
                if name in ("F", "OPCODE"):
                    continue
                if name in layout.placed:
                    f = layout.placed[name]
                    entry["fields"].append({name: {"msb": f.msb, "lsb": f.lsb, "value": "+"}})

            used = set()
            for f in entry["fields"]:
                v = list(f.values())[0]
                used.update(range(v["lsb"], v["msb"] + 1))

            b = 0
            while b < layout.size:
                if b not in used:
                    l = b
                    while b < layout.size and b not in used:
                        b += 1
                    r = b - 1

                    key = (l, r)
                    if key not in res_map:
                        res_map[key] = f"RES{res_id}"
                        res_id += 1

                    name = res_map[key]
                    entry["fields"].append({
                        name: {"msb": r, "lsb": l, "value": "0" * (r - l + 1)}
                    })
                else:
                    b += 1

            entry["fields"].sort(key=lambda x: list(x.values())[0]["msb"], reverse=True)
            out.append(entry)

    return out


def solve(data):
    fields, formats, length = load_data(data)

    opcode = add_opcode(fields, formats)
    matrix, index = build_conflicts(fields, formats)

    layout = Layout(length, index, matrix)

    place_F(layout, formats)
    place_fields(fields, layout, opcode)
    expand_vars(layout, fields)

    return build_output(formats, layout)


if __name__ == "__main__":
    inp = sys.argv[1] if len(sys.argv) > 1 else "input.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "output.json"

    data = json.load(open(inp, encoding="utf-8"))
    result = solve(data)

    with open(out, "w", encoding="utf-8") as f:
        f.write('[\n')
        for i, item in enumerate(result):
            f.write('\t{\n')
            f.write(f'\t\t"insn": "{item["insn"]}",\n')
            f.write('\t\t"fields": [\n')

            for j, fld in enumerate(item["fields"]):
                name = list(fld.keys())[0]
                v = fld[name]
                line = f'\t\t  {{"{name}" :{{"msb": {v["msb"]}, "lsb": {v["lsb"]}, "value": "{v["value"]}"}}}}'
                f.write(line + ("," if j < len(item["fields"]) - 1 else "") + "\n")

            f.write('\t\t]\n')
            f.write('\t}' + ("," if i < len(result) - 1 else "") + '\n')
        f.write(']\n')

    print("OK")
