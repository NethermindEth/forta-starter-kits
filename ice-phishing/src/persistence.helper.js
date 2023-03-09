const { fetchJwt } = require("forta-agent");
const fetch = require("node-fetch");
const { existsSync, readFileSync, writeFileSync } = require("fs");
require("dotenv").config();

class PersistenceHelper {
  databaseUrl;

  constructor(dbUrl) {
    this.databaseUrl = dbUrl;
  }

  async persist(value, key) {
    const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");
    if (!hasLocalNode) {
      const token = await fetchJwt({});

      const headers = { Authorization: `Bearer ${token}` };
      try {
        const response = await fetch(`${this.databaseUrl}${key}`, {
          method: "POST",
          headers: headers,
          body: JSON.stringify(value),
        });

        if (response.ok) {
          console.log(`successfully persisted value to database`);
          return;
        } else {
          console.log(response.status, response.statusText);
        }
      } catch (e) {
        console.log(`failed to persist value to database. Error: ${e}`);
      }
    } else {
      // Persist locally
      writeFileSync(key, JSON.stringify(value));
      return;
    }
  }

  async load(key) {
    const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");
    if (!hasLocalNode) {
      const token = await fetchJwt({});
      const headers = { Authorization: `Bearer ${token}` };
      try {
        const response = await fetch(`${this.databaseUrl}${key}`, { headers });

        if (response.ok) {
          const data = await response.json();
          //const value = parseInt(data);
          console.log("successfully fetched data from database");
          if (key.includes("shard")) {
            return data;
          } else {
            console.log("fetched:", Number(data));
            return Number(data);
          }
        } else {
          console.log(`${key} has no database entry`);
          // If this is the first bot instance that is deployed,
          // the database will not have data to return,
          // thus return zero to assign value to the variables
          // necessary
          if (key.includes("shard")) {
            return {
              approvals: {},
              approvalsERC20: {},
              approvalsERC721: {},
              approvalsForAll721: {},
              approvalsForAll1155: {},
              approvalsInfoSeverity: {},
              approvalsERC20InfoSeverity: {},
              approvalsERC721InfoSeverity: {},
              approvalsForAll721InfoSeverity: {},
              approvalsForAll1155InfoSeverity: {},
              permissions: {},
              permissionsInfoSeverity: {},
              transfers: {},
              transfersLowSeverity: {},
            };
          } else {
            return 0;
          }
        }
      } catch (e) {
        console.log(`Error in fetching data.`);
        throw e;
      }
    } else {
      // Checking if it exists locally
      if (existsSync(key)) {
        let data;
        data = JSON.parse(readFileSync(key).toString());
        return data;
      } else {
        console.log(`file ${key} does not exist`);

        // If this is the first bot instance that is deployed,
        // the database will not have data to return,
        // thus return zero to assign value to the variables
        // necessary
        if (key.includes("shard")) {
          return {
            approvals: {},
            approvalsERC20: {},
            approvalsERC721: {},
            approvalsForAll721: {},
            approvalsForAll1155: {},
            approvalsInfoSeverity: {},
            approvalsERC20InfoSeverity: {},
            approvalsERC721InfoSeverity: {},
            approvalsForAll721InfoSeverity: {},
            approvalsForAll1155InfoSeverity: {},
            permissions: {},
            permissionsInfoSeverity: {},
            transfers: {},
            transfersLowSeverity: {},
          };
        } else {
          return 0;
        }
      }
    }
  }
}

module.exports = {
  PersistenceHelper,
};
