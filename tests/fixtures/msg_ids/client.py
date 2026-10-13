import random

def add_entropy(dev, entropy):
    return dev.call("add_entropy", entropy)

def new_message_id():
    return str(random.randint(100000, 999999))
