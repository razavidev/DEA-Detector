import { PingEmail } from "ping-email";

const pingEmail = new PingEmail({
  port: 25,
  fqdn: "localhost.localdomain",
  sender: "noreply@localhost.localdomain",
  timeout: 10000,
  attempts: 3,
});

async function verifyEmail(email) {
  try {
    console.log(`Checking email: ${email}`);
    const { valid, message } = await pingEmail.ping(email);

    if (valid) {
      console.log(`Result: The email '${email}' appears to be valid.`);
    } else {
      console.error(`Result: The email '${email}' is not valid.`);
      console.error(`Reason: ${message}`);
    }
    return valid

  } catch (error) {
    console.error(`An error occurred while verifying '${email}':`, error);
  }
}

export default verifyEmail