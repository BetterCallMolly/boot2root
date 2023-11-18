import turtle

def parse_instruction(instruction):
    instruction = instruction.strip()
    if instruction.startswith("Tourne"):
        _, direction, _, degrees, _ = instruction.split()
        degrees = int(degrees)
        if direction == "gauche":
            turtle.left(degrees)
        elif direction == "droite":
            turtle.right(degrees)
        else:
            raise ValueError("Invalid direction")
    elif instruction.startswith("Avance"):
        _, spaces, _ = instruction.split()
        spaces = int(spaces)
        turtle.forward(spaces)
    elif instruction.startswith("Recule"):
        _, spaces, _ = instruction.split()
        spaces = int(spaces)
        turtle.backward(spaces)
    else:
        raise ValueError("Invalid instruction {}".format(instruction))

if __name__ == "__main__":
    with open("turtle", "r") as f:
        for line in f:
            if len(line.strip()) == 0:
                continue
            parse_instruction(line)
    turtle.done()