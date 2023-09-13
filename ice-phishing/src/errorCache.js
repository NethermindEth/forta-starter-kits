const errorCache = {
  errors: [],
  add: function (error) {
    this.errors.push(error);
  },
  getAll: function () {
    return this.errors;
  },
  clear: function () {
    this.errors = [];
  },
  len: function () {
    return this.errors.length;
  },
};

module.exports = errorCache;
