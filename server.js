import express from "express";
const app = express();
app.use(express.urlencoded({ extended: false })); // Twilio manda form-urlencoded

app.post("/twilio/sms-inbound", (req, res) => {
  const { From, To, Body } = req.body;
  console.log("📩 INBOUND SMS:", { From, To, Body });
  res.type("text/xml").send("<Response></Response>");
});

app.get("/", (_req, res) => res.send("ok"));

app.listen(process.env.PORT || 3000, () => console.log("listening"));
