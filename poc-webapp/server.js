require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Issuer, generators } = require('openid-client');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, 
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24h
        sameSite: 'lax' //OAuth2 redirects
    },
    name: 'eudi.sid'
}));

app.use(express.static('public'));

let client;

async function initializeOIDC() {
    try {
        const appHost = process.env.APP_HOST || 'localhost';
        const keycloakPort = new URL(process.env.KEYCLOAK_URL).port || '9080';
        const keycloakDiscoveryUrl =
            `http://${appHost}:${keycloakPort}/realms/${process.env.KEYCLOAK_REALM}`;

        const keycloakIssuer = await Issuer.discover(keycloakDiscoveryUrl);

        console.log('✅ Discovered Keycloak issuer:', keycloakIssuer.metadata.issuer);

        client = new keycloakIssuer.Client({
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            redirect_uris: [process.env.REDIRECT_URI],
            response_types: ['code']
        });

        console.log('✅ OIDC Client initialized');
    } catch (error) {
        console.error('❌ Failed to initialize OIDC client:', error.message);
        process.exit(1);
    }
}

function requireAuth(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/');
    }
}


app.get('/', (req, res) => {
    console.log('📍 GET / - Session user:', req.session.user ? 'EXISTS' : 'NOT FOUND');
    console.log('📍 Session ID:', req.sessionID);

    if (req.session.user) {
        console.log('✅ Showing dashboard for user:', req.session.user.username);
        res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
    } else {
        console.log('🔓 No session - showing login page');
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

app.get('/api/user', requireAuth, (req, res) => {
    res.json(req.session.user);
});

app.get('/login', (req, res) => {
    const credentialType = req.query.type || 'pid';
    console.log('🔐 GET /login - Initiating OAuth2 flow');
    console.log('📍 Credential Type:', credentialType);
    console.log('📍 Session ID:', req.sessionID);
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);
    req.session.code_verifier = code_verifier;
    req.session.credential_type = credentialType;
    console.log('💾 Stored code_verifier and credential type in session');
    const authUrl = client.authorizationUrl({
        scope: 'openid profile email',
        code_challenge,
        code_challenge_method: 'S256',
        acr_values: `credential_type:${credentialType}`
    });
    console.log('🔗 Authorization URL:', authUrl);
    console.log('🚀 Redirecting to Keycloak...');
    res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
    console.log('');
    console.log('==========================================');
    console.log('📥 CALLBACK RECEIVED');
    console.log('==========================================');
    console.log('📍 Session ID:', req.sessionID);
    console.log('📍 Query params:', req.query);

    try {
        const params = client.callbackParams(req);
        const code_verifier = req.session.code_verifier;

        console.log('� Code verifier from session:', code_verifier ? 'FOUND' : 'NOT FOUND');

        if (!code_verifier) {
            console.error('❌ No code_verifier in session!');
            throw new Error('Session lost - no code_verifier found');
        }

        console.log('🔄 Exchanging authorization code for tokens...');

        const tokenSet = await client.callback(
            process.env.REDIRECT_URI,
            params,
            { code_verifier }
        );

        console.log('✅ Token exchange successful');

        const claims = tokenSet.claims();
        console.log('👤 User claims:', claims);
        const isDiploma = claims.student_id !== undefined || claims.studentId !== undefined;

        if (isDiploma) {
            const studentId = claims.student_id || claims.studentId;
            const givenName = claims.given_name || claims.firstName;
            const familyName = claims.family_name || claims.lastName;

            req.session.user = {
                sub: claims.sub,
                username: studentId || claims.preferred_username || claims.sub,
                given_name: givenName,
                family_name: familyName,
                name: claims.name || `${givenName || ''} ${familyName || ''}`.trim(),
                email: claims.email,
                student_id: studentId,
                university: claims.university,
                graduation_year: claims.graduation_year || claims.graduationYear,
                is_student: claims.is_student || claims.isStudent,
                issuance_date: claims.issuance_date,
                expiry_date: claims.expiry_date || claims.expiration_date || claims.valid_until,
                certificate_type: claims.certificate_type,
                issuing_country: claims.issuing_country,
                credentialType: 'diploma',
                all_claims: claims
            };
        } else {
            req.session.user = {
                sub: claims.sub,
                username: claims.preferred_username || claims.sub,
                email: claims.email,
                given_name: claims.given_name,
                family_name: claims.family_name,
                name: claims.name || `${claims.given_name || ''} ${claims.family_name || ''}`.trim(),
                birth_date: claims.birth_date || claims.birthdate,
                birth_place: claims.birth_place,
                issuing_country: claims.issuing_country,
                credentialType: 'pid',
                all_claims: claims
            };
        }

        console.log('💾 User stored in session:', req.session.user.username);

        delete req.session.code_verifier;

        req.session.save((err) => {
            if (err) {
                console.error('❌ Error saving session:', err);
                return res.status(500).send('Error saving session');
            }

            console.log('✅ Session saved successfully!');
            console.log('🏠 Serving dashboard directly...');
            console.log('==========================================');
            console.log('');

            res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
        });

    } catch (error) {
        console.error('');
        console.error('==========================================');
        console.error('❌ AUTHENTICATION ERROR');
        console.error('==========================================');
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        console.error('==========================================');
        console.error('');
        res.status(500).send(`
            <html>
                <head>
                    <title>Authentication Error</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            min-height: 100vh;
                            margin: 0;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        }
                        .error-container {
                            background: white;
                            padding: 40px;
                            border-radius: 20px;
                            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                            text-align: center;
                            max-width: 500px;
                        }
                        h1 { color: #e74c3c; }
                        a {
                            display: inline-block;
                            margin-top: 20px;
                            padding: 12px 24px;
                            background: #667eea;
                            color: white;
                            text-decoration: none;
                            border-radius: 8px;
                        }
                    </style>
                </head>
                <body>
                    <div class="error-container">
                        <h1>❌ Authentication Failed</h1>
                        <p>${error.message}</p>
                        <a href="/">← Back to Home</a>
                    </div>
                </body>
            </html>
        `);
    }
});

app.get('/profile', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/logout', (req, res) => {
    const id_token_hint = req.session.user?.all_claims?.id_token;

    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }

        const appHost = process.env.APP_HOST || 'localhost';
        const appBaseUrl = `http://${appHost}:${process.env.PORT || 3000}`;
        const keycloakPort = new URL(process.env.KEYCLOAK_URL).port || '9080';
        const logoutUrl = `http://${appHost}:${keycloakPort}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/logout?post_logout_redirect_uri=${encodeURIComponent(appBaseUrl)}&client_id=${process.env.CLIENT_ID}`;

        console.log('👋 User logged out');
        res.redirect(logoutUrl);
    });
});

async function startServer() {
    await initializeOIDC();

    app.listen(PORT, () => {
        console.log('');
        console.log('==========================================');
        console.log('🚀 EUDI Wallet PoC Server Running');
        console.log('==========================================');
        console.log('');
        console.log(`📍 URL: http://localhost:${PORT}`);
        console.log(`🔐 Keycloak: ${process.env.KEYCLOAK_URL}`);
        console.log(`🏰 Realm: ${process.env.KEYCLOAK_REALM}`);
        console.log(`🆔 Client ID: ${process.env.CLIENT_ID}`);
        console.log('');
        console.log('📋 Available routes:');
        console.log('   GET  /           - Homepage (login or dashboard)');
        console.log('   GET  /login      - Initiate authentication');
        console.log('   GET  /callback   - OAuth2 callback');
        console.log('   GET  /profile    - User profile (protected)');
        console.log('   GET  /logout     - Logout');
        console.log('   GET  /api/user   - Get user info (API)');
        console.log('');
        console.log('==========================================');
    });
}

startServer().catch(console.error);
