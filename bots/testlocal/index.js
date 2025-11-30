const express = require("express");
const app = express();

app.get("/", (req, res) => {
  res.send("Hello World from ADPanel!");
});

const PORT = 3005;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:3005`);
});




















