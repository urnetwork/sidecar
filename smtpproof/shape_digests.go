package smtpproof

// Each catalog shape's circuit digest: the SHA-256 of its compiled circuit as gnark's WriteTo writes it
// (DESIGN-DETAILS 3.2.7). setup -digests writes this file beside a key set's pin, and
// TestShapeDigestsAreThisBuilds holds it to the source, so a circuit changed without it fails there,
// and a host proves nothing for a shape whose digest is not this one. A send loads a shape's cached
// circuit by it without compiling.
//
//go:generate go run ./setup -digests shape_digests.go
var smtpShapeDigests = map[string]string{
	"key-v0304-aes128gcm-c8":   "aa6c9845174dacc55a9463b1958ebe57b9ff9f5841c4a33fd85625d829266b63",
	"key-v0304-chacha20-c2":    "eaeebc2e0137c235e17559a2c3db79d21a465954658c30298b8c91b8869f3702",
	"key-v0303-aes128gcm-c8":   "5f8e50d8347518171fc57bb76bf36ed0a6ee2020e699651d538e7b84255d92e9",
	"env-aes128gcm-s40-c40":    "9caaaba268733fb82449935cb71514f93c25d56618d2580655779b2d14871abc",
	"msg-aes128gcm-s17-c4-h52": "3edb353e462796726c49d7b356567e5ae1d6ff6a95854ad42305751699beeafc",
	"hdr-aes128gcm-c2-r76":     "c9d1c710cf8f57eeb5255138b3d348f6baf1f4b980e02ae6671fd806e25f0b14",
	"body-aes128gcm-c2-b81":    "5c6e32024059e67142d705f8a9ca7c770122b6638cefb57c251f7bfdcea57ef1",
	"env-chacha20-s19-c20":     "522791513708e870a2634c0897845e362808d4ba5ceda7fe0324a7d7199af70d",
	"msg-chacha20-s13-c2-h19":  "f3451a2b1a5732ba327575195fa70321a99ba016c7db7ed963950b51d5e6e14e",
	"hdr-chacha20-c1-r35":      "d66932c9a9eb3dc7ba1aadbe6f4a2bd0b5e687db944bc1f912f963d66f5fa930",
	"body-chacha20-c2-b40":     "8a99abf004e543f2fbec318f5844ae9ab40fc59c063c0f1dade3e1c49c784108",
}
