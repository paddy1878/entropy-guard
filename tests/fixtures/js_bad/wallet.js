// create a private key for the burner wallet
export function privateKeyHex() {
  let out = "";
  for (let i = 0; i < 64; i++) out += Math.floor(Math.random() * 16).toString(16);
  return out;
}
