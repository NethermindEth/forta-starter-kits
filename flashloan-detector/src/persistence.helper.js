const { fetchJwt } = require("forta-agent");
const fetch = require("node-fetch");
const { Headers } = require("node-fetch");
const { existsSync, readFileSync, writeFileSync } = require("fs");
const { Buffer } = require("node:buffer");

async function persist(value, key) {
	const valueToPersist = Buffer.from(value.toString());
    const hasLocalNode = await process.env.hasOwnProperty('LOCAL_NODE');
	if(!hasLocalNode) {
        // fetchJwt() erroring out when running locally,
        // though the docs mention it should return a mock value
        // source: https://docs.forta.network/en/latest/sdk/#fetchjwt
		// const token = await fetchJwt({});
        const token = {token: "jwt-string"} // For testing

        // When logged, headers is an empty object
		const headers = new Headers({"Authorization": `Bearer ${token}`});

        // This fetch() call doesn't seem to return anything, even if it fails
        // Though the README states it should return Promise<Response>
		const response = await fetch(`https://research.forta.network/database/bot/${key}`, { method: 'POST', headers, body: valueToPersist});

        // Per the docs for node-fetch, a Response type has a 
        // .ok property that has a boolean that we could use
        // instead of .status. Need an actual response to test
        if(response.status === 200) {
            return;
        } else {
            console.log(`failed to persist ${value} to database`);
        }
	} else {
		// Persist locally
		writeFileSync(key, valueToPersist);
		return;
	}
}

async function load(key) {
    const hasLocalNode = await process.env.hasOwnProperty('LOCAL_NODE');
	if(!hasLocalNode) {
        // fetchJwt() erroring out when running locally,
        // though the docs mention it should return a mock value
        // source: https://docs.forta.network/en/latest/sdk/#fetchjwt
        // const token = await fetchJwt({});
        const token = { token: "jwt-string" }; // For testing

        // When logged, headers is an empty object
		const headers = new Headers({ "Authorization": `Bearer ${token}` });
        const response = await fetch(`https://research.forta.network/database/bot/${key}`, { headers });

		// Per the docs for node-fetch, a Response type has a 
        // .ok property that has a boolean that we could use
        // instead of .status. Need an actual response to test
		if(response.status === 200 && response.content.length > 0) {
			const bufferString = (await response.buffer()).toString();
			return JSON.parse(bufferString);
		} else {
			console.log(`${key} does not exist`);
		}
	} else {
		// Checking if it exists locally
		if(existsSync(key)) {
			const data = readFileSync(key);
			return JSON.parse(data.toString());
		} else {
			console.log(`file ${key} does not exist`);
		}
	}
};

module.exports = {
    load,
    persist
}