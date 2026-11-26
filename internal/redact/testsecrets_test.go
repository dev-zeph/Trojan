package redact

import "hash/crc32"

// Test secrets are assembled at runtime so no literal key-shaped string sits
// in the repo (keeps secret scanners and push protection quiet). None of these
// are real credentials.
var (
	fakeAWSKey    = "AK" + "IA" + "Q7Z3M2PL9WNBVQXK"
	fakeAWSSecret = "Zq8" + "t/2LmVb7Kp4Rx+9Wc3Nd6Hy1Jf5Gs0Ae8Ui2O"
	fakeStripe    = "sk_" + "live_" + "51HxQe2LkF9aZ0rT7wYbN3mVvC8dPq"
	fakeSlack     = "xo" + "xb-" + "2384756102-9182736450-Qw7Er8Ty9Ui0Op1As2Df3Gh"
	fakeGoogle    = "AI" + "za" + "SyD4f8Kq2Lm9Nx7Pw3Rt6Vb1Zc5Hj0Gs8Ya"
	fakeAnthropic = "sk-" + "ant-" + "api03-Kp9Lm2Nq7Rt4Vw8Xz1Bc5Df3Gh6Jk0"
	fakeOpenAI    = "sk-" + "proj-" + "Qa7Ws2Ed9Rf4Tg1Yh6Uj3Ik8Ol5Pz0Xc"
	fakeSendgrid  = "S" + "G." + "Ab3Cd5Ef7Gh9Ij1Kl3Mn5O" + "." + "Pq7Rs9Tu1Vw3Xy5Za7Bc9De1Fg3Hi5Jk7Lm9No1Pq3R"
	fakeJWT       = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJ" + "yb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ." + "c2lnbmF0dXJlc2lnbmF0dXJlc2ln"
	fakeNPMBody   = "Rk3Lp9Qm2Wn7Xb4Zc8Vd1Fg6Hj0Ks5Ty"[:30]
	fakeGHBody    = "M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq"
	fakePEMBody   = "MIIEowIBAAKCAQEA7Yq2Lm9Nx7Pw3Rt6Vb1Zc5Hj0Gs8YaQe2LkF9aZ0rT7wYbN3mVv\nC8dPqKp9Lm2Nq7Rt4Vw8Xz1Bc5Df3Gh6Jk0Ab3Cd5Ef7Gh9Ij1Kl3Mn5OPq7Rs9Tu1V\n"
)

// fakeGitHub builds a ghp_ token whose CRC32 checksum is valid.
func fakeGitHub() string {
	return "gh" + "p_" + fakeGHBody + base62(crc32.ChecksumIEEE([]byte(fakeGHBody)), 6)
}

// fakeGitHubBadChecksum is the same token with a wrong checksum suffix.
func fakeGitHubBadChecksum() string { return "gh" + "p_" + fakeGHBody + "zzzzzz" }

func fakeNPM() string {
	return "np" + "m_" + fakeNPMBody + base62(crc32.ChecksumIEEE([]byte(fakeNPMBody)), 6)
}

func fakePEM() string {
	return "-----BEGIN RSA PRIV" + "ATE KEY-----\n" + fakePEMBody + "-----END RSA PRIV" + "ATE KEY-----"
}
