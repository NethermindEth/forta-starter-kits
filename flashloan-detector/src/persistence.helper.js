const { fetchJwt } = require("forta-agent");
const { fetch } = require("node-fetch");
const { Headers } = require("node-fetch");
const { existsSync, readFileSync, writeFileSync } = require("fs");
const { Buffer } = require("node:buffer");

class PersistenceHelper {

  async persist(value, key) {
    const valueToPersist = Buffer.from(value.toString());
    const hasLocalNode = await process.env.hasOwnProperty("LOCAL_NODE"); // MOCK INSTANCE NEEDS AWAIT :/
    if (!hasLocalNode) {
      // fetchJwt() erroring out when running locally, (not test suite)
      // though the docs mention it should return a mock value
      // source: https://docs.forta.network/en/latest/sdk/#fetchjwt
      // error: "Could not resolve host 'forta-jwt-provider'.
      // This url host can only be resolved inside of a running scan node"
      const token = await fetchJwt({});

      // When logged, headers is an empty object
      const headers = new Headers({ Authorization: `Bearer ${token}` });
      try {
        const response = await (
          await fetch(`https://research.forta.network/database/bot/${key}`, {
            method: "POST",
            headers,
            body: valueToPersist,
          })
        ).json();

        if (response) {
          return;
        }
      } catch {
        console.log(`failed to persist ${value} to database`);
      }
    } else {
      // Persist locally
      writeFileSync(key, valueToPersist);
      return;
    }
  }

  async load(key) {
    const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");
    if (!hasLocalNode) {
      // fetchJwt() erroring out when running locally,
      // though the docs mention it should return a mock value
      // source: https://docs.forta.network/en/latest/sdk/#fetchjwt
      // error: "Could not resolve host 'forta-jwt-provider'.
      // This url host can only be resolved inside of a running scan node"
      // const token = await fetchJwt({});
      const token = { token: "jwt-string" }; // For testing

      // When logged, headers is an empty object
      const headers = new Headers({ Authorization: `Bearer ${token}` });
      // This instance of fetching from the DB returns a message of:
      // {"message":"unauthorized"}, expectedly. Could be from either
      // the mock Jwt or headers being an empty object, possibly both
      const response = await (await fetch(`https://research.forta.network/database/bot/${key}`, { headers })).json();

      // Response.body should be a string, so this should work
      if (response.ok && response.body.length > 0) {
        const bufferString = (await response.buffer()).toString();
        return JSON.parse(bufferString);
      } else {
        console.log(`${key} has no database entry`);
        // If this is the first bot instance that is deployed,
        // the database will not have data to return,
        // thus return zero to assign value to the variables
        // necessary
        return 0;
      }
    } else {
      // Checking if it exists locally
      if (existsSync(key)) {
        const data = readFileSync(key);
        return JSON.parse(data.toString());
      } else {
        console.log(`file ${key} does not exist`);
      }
    }
  }
}

module.exports = {
  PersistenceHelper,
};
