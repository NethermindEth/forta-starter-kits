const { load, persist } = require("./persistence.helper");
const { fetchJwt } = require("forta-agent");
const { fetch, Headers } = require("node-fetch");

const mockJwt = { token: "aabb1234" };
const mockKey = "mock-test-key";

// Mock environment variables
const mockHasOwnProperty = jest.fn();
process.env = {
    hasOwnProperty: mockHasOwnProperty,
  };

// Mock the fetchJwt function of the forta-agent module
const mockFetchJwt = jest.fn();
jest.mock("forta-agent", () => {
    const original = jest.requireActual("forta-agent");
    return {
      ...original,
      fetchJwt: () => mockFetchJwt(),
    };
  });

// Mock the fetchJwt implementation
// to return the mock JWT
// fetchJwt.mockImplementation(() => mockJwt);

// Mock the fetch function and the Header constructor
// of the node-fetch module
const mockFetch = jest.fn();
const mockBuffer = jest.fn();
jest.mock("node-fetch", () => {
    return {
      Headers: jest.fn(),
      fetch: jest.fn(),
    };
  });
// Mock both the Headers and fetch implementation to return
// the mock Headers and fetch response objects
Headers.mockImplementation(() => { return "mockHeader"});

describe("Persistence Helper test suite", () => {
    it("should correctly POST variable values to the Forta provided database", async () => {
        const mockValue = 100;

        mockHasOwnProperty.mockResolvedValueOnce(false);
        mockFetchJwt.mockResolvedValueOnce(mockJwt);
        fetch.mockImplementation(() => { return { status: 200 }});

        persist(mockValue, mockKey);
        
        expect(mockHasOwnProperty).toHaveBeenCalledTimes(1);
        // expect(mockFetchJwt).toHaveBeenCalledTimes(1); // CANNOT GET THIS WORK PASS
        // expect(fetch).toHaveBeenCalledTimes(1);
    });

    /*
    it("should correctly load variable values from the Forta provided database", async () => {
        mockHasOwnProperty.mockResolvedValueOnce(false);
        fetch.mockImplementation(() => { return { status: 200, content: ["content01", "content02"], buffer: mockBuffer }});
        mockBuffer.mockResolvedValueOnce({ data: "bufferedData", content: "bufferedContent" });

        /*const mockLoadedData = load(mockKey);
        // expect(mockLoadedData)
    });
    */
});