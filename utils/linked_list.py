DECL_TEMPLATE = "t_node %s = { .data = %d, .head = %s, .next = %s };"

class Node:
    def __init__(self, name: str, address: int, value: int, next: int, first: int):
        self.name = name
        self.address = address
        self.value = value
        self.next = next
        self.first = first
    def to_c(self, reference_dict: dict):
        resolved_next_name = "NULL"
        resolved_first_name = "NULL"
        if self.next in reference_dict:
            resolved_next_name = "&" + reference_dict[self.next].name
        if self.first in reference_dict:
            resolved_first_name = "&" + reference_dict[self.first].name
        if self.first == self.address:
            resolved_first_name = "NULL"
        return DECL_TEMPLATE % (self.name, self.value, resolved_first_name, resolved_next_name)

def line2node(line: str) -> Node:
    name, value, first, next, address = line.split(',')
    return Node(name, int(address, 16), int(value, 16), int(next, 16), int(first, 16))

references_dict = {}

reference_table = """
n1,0x24,0x0804b314,0x0804b308,0x0804b320
n21,0x8,0x0804b2e4,0x0804b2fc,0x0804b314
n22,0x32,0x0804b2f0,0x0804b2d8,0x0804b308
n31,0x6,0x0804b2c0,0x0804b29c,0x0804b2e4
n32,0x16,0x0804b290,0x0804b2a8,0x0804b2fc
n33,0x2d,0x0804b2cc,0x0804b284,0x0804b2f0
n34,0x6b,0x0804b2b4,0x0804b278,0x0804b2d8
n41,0x1,0x00000000,0x00000000,0x0804b2c0
n42,0x7,0x00000000,0x00000000,0x0804b29c
n43,0x14,0x00000000,0x00000000,0x0804b290
n44,0x23,0x00000000,0x00000000,0x0804b2a8
n45,0x28,0x00000000,0x00000000,0x0804b2cc
n46,0x2f,0x00000000,0x00000000,0x0804b284
n47,0x63,0x00000000,0x00000000,0x0804b2b4
n48,0x3e9,0x00000000,0x00000000,0x0804b278
"""

if __name__ == "__main__":
    for line in reference_table.split('\n'):
        if line:
            node = line2node(line)
            references_dict[node.address] = node

    for node in references_dict.values():
        print(node.to_c(references_dict))