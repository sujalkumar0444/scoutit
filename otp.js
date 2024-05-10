
import 'dotenv/config.js';
const ACCOUNT_SID = process.env.ACCOUNT_SID;
const AUTH_TOKEN = process.env.AUTH_TOKEN;
const VERIFY_SID = process.env.VERIFY_SID;
import twilio from "twilio";
import { createInterface } from "readline";
const client = twilio(ACCOUNT_SID, AUTH_TOKEN);


client.verify.v2
  .services(VERIFY_SID)
  .verifications.create({ to: "+916303592652", channel: "sms" })
  .then((verification) => console.log(verification.status))
  .then(() => {
    const readline = createInterface({
        input: process.stdin,
        output: process.stdout,
      });
//       client.messages
//   .create({
//      body: 'This is the ship that made the Kessel Run in fourteen parsecs?',
//      from: '+17178975141',
//      to: '+917674802148'
//    })
//   .then(message => console.log(message.sid));
    readline.question("Please enter the OTP:", (otpCode) => {
      client.verify.v2
        .services(VERIFY_SID)
        .verificationChecks.create({ to: "+916303592652", code: otpCode })
        .then((verification_check) => console.log(verification_check.status))
        .then(() => readline.close());
    });
  });