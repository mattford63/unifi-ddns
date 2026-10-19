class BadRequestException extends Error {
	constructor(reason) {
		super(reason);
		this.status = 400;
		this.statusText = "Bad Request";
	}
}

class CloudflareApiException extends Error {
	constructor(reason) {
		super(reason);
		this.status = 500;
		this.statusText = "Internal Server Error";
	}
}

class Cloudflare {
	constructor(options) {
		this.cloudflare_url = "https://api.cloudflare.com/client/v4";
		this.token = options.token;
	}

	async findZone(name) {
		const response = await this._fetchWithToken(`zones?name=${name}`);
		const body = await response.json();
		if (!body.success || body.result.length === 0) {
			throw new CloudflareApiException(`Failed to find zone '${name}'`);
		}
		return body.result[0];
	}

	async findRecord(zone, name, isIPV4 = true) {
		const rrType = isIPV4 ? "A" : "AAAA";
		const response = await this._fetchWithToken(`zones/${zone.id}/dns_records?name=${name}`);
		const body = await response.json();
		if (!body.success || body.result.length === 0) {
			throw new CloudflareApiException(`Failed to find dns record '${name}'`);
		}
		return body.result?.filter(rr => rr.type === rrType)[0];
	}

	async updateRecord(record, value) {
		record.content = value;
		const response = await this._fetchWithToken(
			`zones/${record.zone_id}/dns_records/${record.id}`,
			{
				method: "PUT",
				body: JSON.stringify(record),
			}
		);
		const body = await response.json();
		if (!body.success) {
			throw new CloudflareApiException("Failed to update dns record");
		}
		return body.result[0];
	}

	async _fetchWithToken(endpoint, options = {}) {
		const url = `${this.cloudflare_url}/${endpoint}`;
		options.headers = {
			...options.headers,
			"Content-Type": "application/json",
			Authorization: `Bearer ${this.token}`,
		};
		return fetch(url, options);
	}
}

// A router with no address on a WAN (e.g. an unplugged failover port) still
// calls in, substituting 0.0.0.0 or a private/CGNAT address for %i. Writing
// that would take the hostname offline, so only accept public unicast IPs.
function parseIPv4(ip) {
	const parts = ip.split(".");
	if (parts.length !== 4 || !parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null;
	return parts.map(Number);
}

function isPublicIPv4(ip) {
	const o = parseIPv4(ip);
	if (!o) return false;
	const [a, b] = o;
	return !(
		a === 0 || // 0.0.0.0/8 "this network"
		a === 10 || // 10.0.0.0/8 private
		(a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 CGNAT
		a === 127 || // 127.0.0.0/8 loopback
		(a === 169 && b === 254) || // 169.254.0.0/16 link-local
		(a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12 private
		(a === 192 && b === 168) || // 192.168.0.0/16 private
		a >= 224 // multicast, reserved, broadcast
	);
}

function isPublicIPv6(ip) {
	if (!/^[0-9a-f:]+$/i.test(ip) || !ip.includes(":")) return false;
	const first = parseInt(ip.split(":")[0] || "0", 16);
	return !(
		/^[0:]+$/.test(ip) || // :: unspecified
		/^[0:]+1$/.test(ip) || // ::1 loopback
		(first & 0xfe00) === 0xfc00 || // fc00::/7 unique local
		(first & 0xffc0) === 0xfe80 || // fe80::/10 link-local
		(first & 0xff00) === 0xff00 // ff00::/8 multicast
	);
}

function requirePublicIp(ip) {
	if (!(ip.includes(".") ? isPublicIPv4(ip) : isPublicIPv6(ip))) {
		throw new BadRequestException(`Refusing to set non-public IP address '${ip}'`);
	}
}

function requireHttps(request) {
	const { protocol } = new URL(request.url);
	const forwardedProtocol = request.headers.get("x-forwarded-proto");

	if (protocol !== "https:" || forwardedProtocol !== "https") {
		throw new BadRequestException("Please use a HTTPS connection.");
	}
}

function parseBasicAuth(request) {
	const authorization = request.headers.get("Authorization");
	if (!authorization) return {};

	const [, data] = authorization?.split(" ");
	const decoded = atob(data);
	const index = decoded.indexOf(":");

	if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
		throw new BadRequestException("Invalid authorization value.");
	}

	return {
		username: decoded?.substring(0, index),
		password: decoded?.substring(index + 1),
	};
}

async function handleRequest(request) {
	requireHttps(request);
	const { pathname } = new URL(request.url);

	if (pathname === "/favicon.ico" || pathname === "/robots.txt") {
		return new Response(null, { status: 204 });
	}

	if (!pathname.endsWith("/update")) {
		return new Response("Not Found.", { status: 404 });
	}

	if (!request.headers.has("Authorization") && !request.url.includes("token=")) {
		return new Response("Not Found.", { status: 404 });
	}

	const { username, password } = parseBasicAuth(request);
	const url = new URL(request.url);
	const params = url.searchParams;

	// duckdns uses ?token=
	const token = password || params?.get("token");

	// dyndns uses ?hostname= and ?myip=
	// duckdns uses ?domains= and ?ip=
	// ydns uses ?host=
	const hostnameParam = params?.get("hostname") || params?.get("host") || params?.get("domains");
	const hostnames = hostnameParam?.split(",");

	// fallback to connecting IP address
	const ipsParam = params.get("ips") || params.get("ip") || params.get("myip") || request.headers.get("Cf-Connecting-Ip");
   	const ips = ipsParam?.split(",");

	if (!hostnames || hostnames.length === 0 || !ips || ips.length === 0) {
	        throw new BadRequestException("You must specify both hostname(s) and IP address(es)");
	}

	// Check every IP before touching any record, so a bad one can't leave a partial update
	ips.forEach(ip => requirePublicIp(ip.trim()));

	// Iterate over each IP and update DNS records for all hostnames
    	for (const ip of ips) {
		await informAPI(hostnames, ip.trim(), username, token);
    	}
	return new Response("good", {
        	status: 200,
		headers: {
          	  	"Content-Type": "text/plain;charset=UTF-8",
        	    	"Cache-Control": "no-store",
        	},
    	});
}

async function informAPI(hostnames, ip, name, token) {

	const cloudflare = new Cloudflare({ token });

	const isIPV4 = ip.includes("."); //poorman's ipv4 check

	const zones = new Map();

	for (const hostname of hostnames) {
		const domainName = name && hostname.endsWith(name) ? name : hostname.replace(/.*?([^.]+\.[^.]+)$/, "$1");

		if (!zones.has(domainName)) zones.set(domainName, await cloudflare.findZone(domainName));

		const zone = zones.get(domainName);
		const record = await cloudflare.findRecord(zone, hostname, isIPV4);
		await cloudflare.updateRecord(record, ip);
	}
}

export default {
	async fetch(request, env, ctx) {
		return handleRequest(request).catch((err) => {
			console.error(err.constructor.name, err);
			const message = err.reason || err.stack || "Unknown Error";

			return new Response(message, {
				status: err.status || 500,
				statusText: err.statusText || null,
				headers: {
					"Content-Type": "text/plain;charset=UTF-8",
					"Cache-Control": "no-store",
					"Content-Length": message.length,
				},
			});
		});
	},
};
