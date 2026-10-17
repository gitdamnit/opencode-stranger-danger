// Dirty fixture — contains defanged secret-like values for scanner tests.
// These are intentionally NOT valid provider key formats, so GitHub Push Protection
// will not block the repository push.

export const dirtyContent = `
// AWS Access Key - defanged test fixture
const AWS_KEY = "AWS_FAKE_ACCESS_KEY_FOR_TESTS_NOT_REAL";

// GitHub Personal Access Token - defanged test fixture
const GH_TOKEN = "GITHUB_FAKE_TOKEN_FOR_TESTS_NOT_REAL";

// OpenAI API Key - defanged test fixture
const OPENAI_KEY = "OPENAI_FAKE_KEY_FOR_TESTS_NOT_REAL";

// Anthropic API Key - defanged test fixture
const ANTHROPIC_KEY = "ANTHROPIC_FAKE_KEY_FOR_TESTS_NOT_REAL";

// Stripe Secret Key - defanged test fixture
const STRIPE_KEY = "STRIPE_FAKE_SECRET_KEY_FOR_TESTS_NOT_REAL";

// Groq API Key - defanged test fixture
const GROQ_KEY = "GROQ_FAKE_KEY_FOR_TESTS_NOT_REAL";

// MongoDB connection string with fake credentials
const MONGO_URI = "mongodb+srv://fake_user:fake_password@cluster0.example.invalid/mydb";

// Supabase token - defanged test fixture
const SUPABASE_TOKEN = "SUPABASE_FAKE_TOKEN_FOR_TESTS_NOT_REAL";

// Private Key - defanged test fixture. Synthetic body is not a real key; it is
// long enough (>= 64 chars) to satisfy the PEM detection rule's body length.
const PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\\nRkFLRV9QUklWQVRFX0tFWV9GT1JfVEVTVFNfT05MWV9ET19OT1RfVVNFXzAwMDAwMDAwMDAwMDAwMDA=\\n-----END PRIVATE KEY-----";

// JWT token - defanged test fixture
const JWT_TOKEN = "JWT_FAKE_TOKEN_FOR_TESTS_NOT_REAL";
`;
