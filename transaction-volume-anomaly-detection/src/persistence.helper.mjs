const dotenv = require("dotenv");
const { fetchJwt } = require("forta-agent");
import fetch from 'node-fetch';
const fs = require("fs");

dotenv.config();

class PersistenceHelper {
  constructor(databaseUrl) {
    this.databaseUrl = databaseUrl;
  }

  async persist(value, key) {
    const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");
    if (!hasLocalNode) {
      try {
        const token = await fetchJwt({});
        const headers = { Authorization: `Bearer ${token}` };
        const response = await fetch(`${this.databaseUrl}${key}`, {
          method: "POST",
          headers,
          body: JSON.stringify(value),
        });

        if (response.ok) {
          console.log(
            key.includes("nm-transaction-volume")
              ? "successfully persisted addresses to database"
              : "successfully persisted transfers to database"
          );
          return;
        } else {
          console.log(response.status, response.statusText);
        }
      } catch (e) {
        console.log(`failed to persist value to database. Error: ${e}`);
      }
    } else {
      fs.writeFileSync(key, JSON.stringify(value));
    }
  }

  async load(key) {
    const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");
    if (!hasLocalNode) {
      try {
        const token = await fetchJwt({});
        const headers = { Authorization: `Bearer ${token}` };
        const response = await fetch(`${this.databaseUrl}${key}`, { headers });

        if (response.ok) {
          const data = await response.json();
          console.log(
            key.includes("nm-transaction-volume")
              ? "successfully fetched addresses from database"
              : "successfully fetched transfers from database"
          );
          return data;
        } else {
          console.log(`${key} has no database entry`, response.status, response.statusText);
          return key.includes("nm-transaction-volume") ? [] : {};
        }
      } catch (e) {
        console.log(`Error in fetching data: ${e}`);
        throw e;
      }
    } else {
      if (fs.existsSync(key)) {
        return JSON.parse(fs.readFileSync(key));
      } else {
        console.log(`file ${key} does not exist`);
        return key.includes("nm-transaction-volume") ? [] : {};
      }
    }
  }
}

module.exports = PersistenceHelper;
