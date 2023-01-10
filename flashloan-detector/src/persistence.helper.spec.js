const { PersistenceHelper } = require("./persistence.helper");
const { fetchJwt } = require("forta-agent");
const fetch = require("node-fetch");
// const { Headers } = require("node-fetch");
const { Buffer } = require("node:buffer");

const mockDbUrl = "databaseurl.com/";

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

// Mock the fetch function and the Header constructor
// of the node-fetch module
const mockFetch = jest.fn();
const { Response } = jest.requireActual("node-fetch");
jest.mock("node-fetch", () => {
  return {
    Headers: jest.fn(),
    fetch: () => mockFetch(),
  };
});

describe("Persistence Helper test suite", () => {
  let persistenceHelper;

  beforeAll(() => {
    persistenceHelper = new PersistenceHelper(mockDbUrl);
  });

  afterEach(() => {
    mockHasOwnProperty.mockClear();
    mockFetchJwt.mockClear();
    mockFetch.mockClear();
  });

  it("should correctly POST a value to the database", async () => {
    const mockValue = 101;

    const mockResponseInit = { status: 202 };
    const mockPostMethodResponse = { data: "4234" };
    const mockFetchResponse = new Response(JSON.stringify(mockPostMethodResponse), mockResponseInit);

    mockHasOwnProperty.mockReturnValueOnce(false);
    mockFetchJwt.mockResolvedValueOnce(mockJwt);
    mockFetch.mockResolvedValueOnce(Promise.resolve(mockFetchResponse));

    await persistenceHelper.persist(mockValue, mockKey);

    expect(mockHasOwnProperty).toHaveBeenCalledTimes(1);
    expect(mockFetchJwt).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    // STRUGGLING TO CONFIRM FETCH WAS CALLED WITH THE RIGHT ARGS
    // expect(mockFetch).toHaveBeenCalledWith(`${mockDbUrl}${mockKey}`, {
    // method: "POST",
    // headers: new Headers({ Authorization: `Bearer ${mockJwt}` }),
    // body: Buffer.from(mockValue.toString()),
    // });
  });

  it("should fail to POST a value to the database", async () => {
    const mockValue = 202;

    const mockResponseInit = { status: 305 };
    const mockPostMethodResponse = { data: "4234" };
    const mockFetchResponse = new Response(JSON.stringify(mockPostMethodResponse), mockResponseInit);

    mockHasOwnProperty.mockReturnValueOnce(false);
    mockFetchJwt.mockResolvedValueOnce(mockJwt);
    mockFetch.mockResolvedValueOnce(mockFetchResponse);

    await persistenceHelper.persist(mockValue, mockKey);

    expect(mockHasOwnProperty).toHaveBeenCalledTimes(1);
    expect(mockFetchJwt).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  /*
  it("should correctly load variable values from the database", async () => {
      const mockBuffer = jest.fn();
      const mockData = 4234;

      const mockResponseInit = { status: 207 };
      const mockPostMethodResponse = Buffer.from(mockData.toString());
      const mockFetchResponse = new Response(JSON.stringify(mockPostMethodResponse), mockResponseInit);

      mockHasOwnProperty.mockReturnValueOnce(false);
      mockFetchJwt.mockResolvedValueOnce(mockJwt);
      mockFetch.mockResolvedValueOnce(mockFetchResponse);
      mockBuffer.mockResolvedValueOnce("buffer return value");

      // fetch.mockImplementation(() => { return { status: 200, content: ["content01", "content02"], buffer: mockBuffer }});
      // mockBuffer.mockResolvedValueOnce({ data: "bufferedData", content: "bufferedContent" });

      await persistenceHelper.load(mockKey);
      // expect(mockLoadedData)
  });
  */

  it("should fail to load values from the database, but return zero", async () => {
    const mockData = 4234;

    const mockResponseInit = { status: 308 };
    const mockPostMethodResponse = Buffer.from(mockData.toString());
    const mockFetchResponse = new Response(JSON.stringify(mockPostMethodResponse), mockResponseInit);

    mockHasOwnProperty.mockReturnValueOnce(false);
    mockFetchJwt.mockResolvedValueOnce(mockJwt);
    mockFetch.mockResolvedValueOnce(mockFetchResponse);

    const fetchedValue = await persistenceHelper.load(mockKey);
    expect(fetchedValue).toStrictEqual(0);
  });
});
