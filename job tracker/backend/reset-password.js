const bcrypt = require("bcrypt");
const db = require("./models/db");

(async () => {
  const email = "Brianb@allweatherseal.com".trim().toLowerCase();
  const plainPassword = "newpassword123";
  const hash = await bcrypt.hash(plainPassword, 10);

  db.get(
    "SELECT id FROM users WHERE LOWER(TRIM(email)) = ?",
    [email],
    (err, user) => {
      if (err) {
        console.log("SELECT ERROR:", err.message);
        process.exit(1);
      }

      if (user) {
        db.run(
          "UPDATE users SET password = ? WHERE id = ?",
          [hash, user.id],
          function (updateErr) {
            if (updateErr) {
              console.log("UPDATE ERROR:", updateErr.message);
              process.exit(1);
            } else {
              console.log("Password updated");
              process.exit(0);
            }
          }
        );
      } else {
        db.run(
          "INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)",
          ["Brian", email, null, hash, "admin"],
          function (insertErr) {
            if (insertErr) {
              console.log("INSERT ERROR:", insertErr.message);
              process.exit(1);
            } else {
              console.log("Admin created and password set");
              process.exit(0);
            }
          }
        );
      }
    }
  );
})();