const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const { findUserByGoogleId, createUserFromGoogle, findUserByDiscordId, createUserFromDiscord, findUserByGithubId, createUserFromGithub } = require('../models/User');

// =============================================================================
// TODO 1: Configuration de la stratégie Google OAuth 2.0
// =============================================================================
// Instructions:
// 1. Importer GoogleStrategy depuis 'passport-google-oauth20'
// 2. Configurer passport.use() avec new GoogleStrategy()
// 3. Options à passer :
//    - clientID: process.env.GOOGLE_CLIENT_ID
//    - clientSecret: process.env.GOOGLE_CLIENT_SECRET
//    - callbackURL: process.env.GOOGLE_CALLBACK_URL
//    - passReqToCallback: true (pour accéder à req.app.locals.db)
// 4. Fonction callback async (req, accessToken, refreshToken, profile, done) :
//    a. Récupérer db depuis req.app.locals.db
//    b. Chercher l'utilisateur par googleId (profile.id) avec findUserByGoogleId()
//    c. Si l'utilisateur n'existe pas, le créer avec createUserFromGoogle()
//       - googleId: profile.id
//       - email: profile.emails[0].value
//       - name: profile.displayName
//       - picture: profile.photos[0].value
//    d. Appeler done(null, user) pour retourner l'utilisateur
//    e. En cas d'erreur, appeler done(error, null)
//
// Documentation : https://www.passportjs.org/packages/passport-google-oauth20/
// =============================================================================

// Configuration de la stratégie Google OAuth 2.0
passport.use(new GoogleStrategy({
	clientID: process.env.GOOGLE_CLIENT_ID,
	clientSecret: process.env.GOOGLE_CLIENT_SECRET,
	callbackURL: process.env.GOOGLE_CALLBACK_URL,
	passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
	try {
		const db = req.app.locals.db;

		// Chercher l'utilisateur par googleId
		let user = await findUserByGoogleId(db, profile.id);

		// Si non trouvé, créer un nouvel utilisateur depuis les infos Google
		if (!user) {
			const email = profile.emails && profile.emails[0] && profile.emails[0].value;
			const picture = profile.photos && profile.photos[0] && profile.photos[0].value;

			user = await createUserFromGoogle(db, {
				googleId: profile.id,
				email,
				name: profile.displayName,
				picture
			});
		}

		return done(null, user);
	} catch (error) {
		return done(error, null);
	}
}));

// Configuration de la stratégie Discord OAuth2
passport.use(new DiscordStrategy({
	clientID: process.env.DISCORD_CLIENT_ID,
	clientSecret: process.env.DISCORD_CLIENT_SECRET,
	callbackURL: process.env.DISCORD_CALLBACK_URL,
	scope: ['identify', 'email'],
	passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
	try {
		const db = req.app.locals.db;

		let user = await findUserByDiscordId(db, profile.id);

		if (!user) {
			// profile may contain username and discriminator; build a name
			const name = profile.username ? `${profile.username}#${profile.discriminator || ''}` : profile.username;
			const email = profile.email || (profile.emails && profile.emails[0] && profile.emails[0].value);
			// avatar url construction
			const avatar = profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null;

			user = await createUserFromDiscord(db, {
				discordId: profile.id,
				email,
				name,
				avatar
			});
		}

		return done(null, user);
	} catch (error) {
		return done(error, null);
	}
}));

// ⚠️ PAS de serializeUser/deserializeUser car on utilise JWT (stateless)
// Ces fonctions sont uniquement pour les sessions

// Configuration de la stratégie GitHub OAuth2
passport.use(new GitHubStrategy({
	clientID: process.env.GITHUB_CLIENT_ID,
	clientSecret: process.env.GITHUB_CLIENT_SECRET,
	callbackURL: process.env.GITHUB_CALLBACK_URL,
	passReqToCallback: true,
	scope: ['user:email']
}, async (req, accessToken, refreshToken, profile, done) => {
	try {
		const db = req.app.locals.db;

		let user = await findUserByGithubId(db, profile.id);

		if (!user) {
			// profile may contain displayName, username; avatar is profile.photos[0]
			const name = profile.displayName || profile.username;
			const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || null;
			const avatar = (profile.photos && profile.photos[0] && profile.photos[0].value) || null;

			user = await createUserFromGithub(db, {
				githubId: profile.id,
				email,
				name,
				avatar
			});
		}

		return done(null, user);
	} catch (error) {
		return done(error, null);
	}
}));

module.exports = passport;

