import petlib.bn


def generate_random_bn(order: petlib.bn.Bn) -> petlib.bn.Bn:
    return _generate_random_bn(order)


def _generate_random_bn(order: petlib.bn.Bn) -> petlib.bn.Bn:
    # Defined as a private method for easy monkeypatching
    return order.random()
