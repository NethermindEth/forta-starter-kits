const { fetchJwt } = require("forta-agent");
const { readFileSync } = require("fs");
require("dotenv").config();

const OWNER_DB = "https://research.forta.network/database/owner/";
const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");

const getToken = async () => {
  const tk = await fetchJwt({});
  return { Authorization: `Bearer ${tk}` };
};

const loadJson = async (key) => {
  if (hasLocalNode) {
    const data = readFileSync("secrets.json", "utf8");
    return JSON.parse(data);
  } else {
    try {
      const response = await fetch(`${OWNER_DB}${key}`, {
        headers: await getToken(),
      });
      if (response.ok) {
        return response.json();
      } else {
        throw new Error(`Error loading JSON from owner db: ${response.status}, ${response.statusText}`);
      }
    } catch (error) {
      throw new Error(`Error loading JSON from owner db: ${error}`);
    }
  }
};

const getSecrets = async () => {
  return await loadJson("secrets.json");
};

module.exports = {
  getSecrets,
};
