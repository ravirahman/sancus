type MaybeUndefined<T> = T | undefined;

export default <ValueType>(input: MaybeUndefined<ValueType>): ValueType => {
  if (input === undefined) {
    throw new Error('required value is undefined');
  }
  return input;
};
