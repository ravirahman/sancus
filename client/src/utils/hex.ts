const bufToHex = (buffer: ArrayBuffer) => {
  return Array.prototype.map.call(new Uint8Array(buffer), (x) => {
    return (`00${x.toString(16)}`).slice(-2);
  }).join('');
};

const hexToBuf = (hexString: string) => {
  const bytes = new Uint8Array(Math.ceil(hexString.length / 2));
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
  }
  return bytes;
};

export { bufToHex, hexToBuf };
