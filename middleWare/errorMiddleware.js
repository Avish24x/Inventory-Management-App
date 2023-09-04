const errorHandler = (err, req, res, next) => {
  // This code snippet assigns the value of 'res.statusCode' to the 'statusCode' variable
  // if 'res.statusCode' is truthy (i.e., not undefined, null, 0, false, or an empty string).
  // Otherwise, it assigns the value 500 to 'statusCode'.
  const statusCode = res.statusCode ? res.statusCode : 500;

  res.status(statusCode);

  // This code sends a JSON response with an error message and, in development mode,
  // includes the error stack trace.
  // It checks the value of 'process.env.NODE_ENV' to determine whether to include the stack trace.

  res.json({
    message: err.message, // The error message is included in the response.
    stack: process.env.NODE_ENV === "development" ? err.stack : null, // In development, the stack trace is included; otherwise, it's set to null.
  });
};

module.exports = errorHandler;
