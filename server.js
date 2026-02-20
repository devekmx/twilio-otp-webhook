import express from "express";
const app = express();
app.use(express.urlencoded({ extended: false })); // Twilio manda form-urlencoded

app.post("/twilio/sms-inbound", (req, res) => {
  const { From, To, Body } = req.body;
  console.log("📩 INBOUND SMS:", { From, To, Body });
  res.type("text/xml").send("<Response></Response>");
});

app.post("/twilio/voice-otp", (req, res) => {
  res.type("text/xml").send(`
<Response>
  <Record maxLength="90" playBeep="false" />
  <Hangup/>
</Response>
`.trim());
});

app.post("/twilio/inbound", (req, res) => {
  const { From, To, Body, ProfileName } = req.body;
  console.log("💬 INBOUND", { From, To, Body, ProfileName });
  res.type("text/xml").send("<Response></Response>");
});

app.get("/", (_req, res) => res.send("ok"));

app.listen(process.env.PORT || 3000, () => console.log("listening"));
