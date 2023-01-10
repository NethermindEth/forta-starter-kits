const { fetchJwt } = require("forta-agent");
const { fetch } = require("node-fetch");
const { Headers } = require("node-fetch");
const { existsSync, readFileSync, writeFileSync } = require("fs");
const { Buffer } = require("node:buffer");

class PersistenceHelper {
  databaseUrl;

  constructor(dbUrl) {
    this.databaseUrl = dbUrl;
  }

  async persist(value, key) {
    const valueToPersist = Buffer.from(value.toString());
    const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");
    // console.log(`hasLocalNode: ${hasLocalNode}`);
    if (!hasLocalNode) {
      const token = await fetchJwt({});
      // console.log(`token: ${JSON.stringify(token)}`);

      const headers = new Headers({ Authorization: `Bearer ${token}` });
      try {
        const response = await fetch(`${this.databaseUrl}${key}`, {
          method: "POST",
          headers: headers,
          body: valueToPersist,
        });

        console.log(`response.ok: ${JSON.stringify(response.ok)}`);

        if (response.ok) {
          console.log(`succesfully persisted ${value} to database`);
          return;
        }
      } catch (e) {
        console.log(`failed to persist ${value} to database. Error: ${e}`);
      }
    } else {
      // Persist locally
      writeFileSync(key, valueToPersist);
      return;
    }
  }

  async load(key) {
    const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");
    // console.log(`hasLocalNode: ${hasLocalNode}`);
    if (!hasLocalNode) {
      const token = await fetchJwt({});
      // console.log(`token: ${JSON.stringify(token)}`);

      const headers = new Headers({ Authorization: `Bearer ${token}` });
      try {
        const response = await fetch(`${this.databaseUrl}${key}`, { headers });
        // console.log(`response.ok: ${JSON.stringify(response.ok)}`);

        if (response.ok) {
          const data = await response.json();
          // console.log(`data: ${JSON.stringify(data)}`);
          const bufferString = (await data.buffer()).toString();
          // console.log(`bufferString: ${bufferString}`);
          console.log(`successfully fetched value from database`);
          return JSON.parse(bufferString);
        } else {
          console.log(`${key} has no database entry`);
          // If this is the first bot instance that is deployed,
          // the database will not have data to return,
          // thus return zero to assign value to the variables
          // necessary
          return 0;
        }
      } catch (e) {
        console.log(`Error in fetching data.`);
        throw e;
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
