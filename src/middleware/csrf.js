"use strict";

const winston = require("winston");
const { csrfSync } = require("csrf-sync");

const { generateToken, csrfSynchronisedProtection, isRequestValid } = csrfSync({
	getTokenFromRequest: (req) => {
		if (req.headers["x-csrf-token"]) {
			return req.headers["x-csrf-token"];
		} else if (req.body && req.body.csrf_token) {
			return req.body.csrf_token;
		} else if (req.body && req.body._csrf) {
			return req.body._csrf;
		} else if (req.query && req.query._csrf) {
			return req.query._csrf;
		}
	},
	getOrigin: (req) => {
		const proto = req.headers["x-forwarded-proto"] || req.protocol;
		winston.info("[CSRF] Protocol:", proto);
		return `${proto}://${req.get("host")}`;
	},
	size: 64,
});

module.exports = {
	generateToken,
	csrfSynchronisedProtection,
	isRequestValid,
};
