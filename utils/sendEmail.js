const nodemailer = require("nodemailer");

const sendEmail = async (subject, message, send_to, sent_from, reply_to) => {
  // create email transportor
  // carries your email from one plcae to another

  const nodemailer = require("nodemailer");

  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: 587, // Use the appropriate port for TLS (587 for TLS)
    secure: false, // Use TLS, not SSL
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  //   Option for sending email
  const options = {
    //   sender address and name
    from: sent_from,
    to: send_to,
    replyTo: reply_to,
    subject: subject,
    html: message,
  };

  //   send email
  transporter.sendMail(options, function (err, info) {
    if (err) {
      console.log(err);
    } else {
      console.log(info);
    }
  });
};

module.exports = sendEmail;
