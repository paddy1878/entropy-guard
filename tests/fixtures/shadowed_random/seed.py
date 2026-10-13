import random
def confirm_mnemonic_words(words):
    order = list(range(len(words)))
    random.shuffle(order)
    return order
