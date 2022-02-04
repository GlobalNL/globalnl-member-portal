/**
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"use strict";

const functions = require("firebase-functions");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

//Mailgun Setup
const mailgunKey = functions.config().mailgun.key;
var mailgun = require("mailgun-js")({
  apiKey: mailgunKey,
  domain: "email.globalnl.com"
});

//Mailchimp Setup
const mailchimpKey = functions.config().mailchimp.key;
const mailchimpListID = functions.config().mailchimp.list_id;
const Mailchimp = require('mailchimp-api-v3')
const mailchimp = new Mailchimp(mailchimpKey);

// Firebase Setup
const admin = require("firebase-admin");


var serviceAccount = require(`./${functions.config().project.name}-service-account.json`);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${functions.config().project.name}.firebaseio.com`,
  storageBucket: `https://${functions.config().project.name}.appspot.com`
});
var db = admin.firestore();
const settings = { timestampsInSnapshots: true };
db.settings(settings);

var member = {};
var private_data = {};

const passport = require("passport");
const LinkedInStrategy = require("passport-linkedin-oauth2").Strategy;

/*
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});
*/


// [START express and related modules import]
const express = require('express');
const app = express();
//const cors = require('cors')({origin: true});
//app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
//const session = require('express-session')
//app.use(session({ secret: functions.config().session.secret }));
app.use(passport.initialize());
//app.use(passport.session());

passport.use(
  new LinkedInStrategy(
    {
      clientID: functions.config().linkedin.client_id,
      clientSecret: functions.config().linkedin.client_secret,
      callbackURL: `${functions.config().project.base_url}/auth/linkedin/callback`,
      scope: ["r_emailaddress", "r_liteprofile"],
    },
    (
      accessToken,
      refreshToken,
      profile,
      done
    ) => {
      process.nextTick(() => {
        return done(null, profile);
      });
    }
  )
);

/**
 * Sends welcome email to new users
 */

exports.sendWelcomeEmail = functions.auth.user().onCreate(user => {
  const email = user.email; // The email of the user.
  const displayName = user.displayName; // The display name of the user.
  var promiseArray = [];
  promiseArray.push(sendWelcomeEmail(email, displayName));
  promiseArray.push(mailchimp.post(
			`/lists/${mailchimpListID}/members`,
			{
				email_address: email,
				status: 'subscribed',
				merge_fields:{FNAME: displayName}
			}
			)
			.then((response)=>{
				console.log(email + ' added to Mailchimp');
				//console.log(response);
			}));
    return Promise.all(promiseArray)
	.catch(err => {
    if(err.detail)
		  console.error(err.detail);
    else
      console.error('Mailchimp error');
	});
});

exports.sendMessageToUser = functions.https.onCall((data, context) => {
  const { auth } = context,
    isAuthed = Boolean(auth),
    MAX_MESSAGES_PER_DAY = 25;

  if (!isAuthed || !data || !data.toUserId || !data.message) {
    console.log("Error sending message:", isAuthed, data);
    return;
  }

  const fromUserId = auth.uid,
    { toUserId, message } = data,
    members = db.collection("members"),
    privateData = db.collection("private_data"),
    fromUserPrivateDataDoc = privateData.doc(fromUserId);

  return privateData.doc(fromUserId).get().then(fromUserSnapshot => {
    const fromUserPrivateData = fromUserSnapshot.data(),
      today = new Date();

    let { send_message_date, send_message_count } = fromUserPrivateData;

    const previousSendDate = Boolean(send_message_date) && send_message_date.toDate(),
      sendingAnotherMessageToday = Boolean(previousSendDate) &&
        previousSendDate.getUTCFullYear() === today.getUTCFullYear() &&
        previousSendDate.getUTCMonth() === today.getUTCMonth() &&
        previousSendDate.getUTCDate() === today.getUTCDate();

    if (sendingAnotherMessageToday) {
      if (send_message_count >= MAX_MESSAGES_PER_DAY) {
        console.log("Error sending message:", fromUserId, "exceeded message limit of", MAX_MESSAGES_PER_DAY);
        return;
      }

      send_message_count += 1;
    } else {
      send_message_date = today;
      send_message_count = 1;
    }

    const upateSendMessageDateAndCount = fromUserPrivateDataDoc.set({ send_message_date, send_message_count }, { merge: true }),
      getFromUser = members.doc(fromUserId).get(),
      getToUser = members.doc(toUserId).get(),
      getToUserPrivateData = privateData.doc(toUserId).get();

    return Promise.all([upateSendMessageDateAndCount, getFromUser, getToUser, getToUserPrivateData])
      .then(
        ([
          _,
          fromUserMemberDoc,
          toUserMemberDoc,
          toUserPrivateDataDoc
        ]) => {
          const fromUserMemberData = fromUserMemberDoc.data(),
            fromDisplayName = fromUserMemberData.display_name || `${fromUserMemberData.first_name} ${fromUserMemberData.last_name}`,
            mailOptions = {
              from: `${fromDisplayName} <connect@globalnl.com>`,
              to: `${toUserMemberDoc.data().display_name} <${
                toUserPrivateDataDoc.data().email
                }>`,
              subject: `${fromDisplayName} sent you a message on GlobalNL`,
              text: `${message}
---
You are receiving this because a member contacted you through the GlobalNL members portal at http://members.globalnl.com
Reply to this email to respond, your email address will be viewable by the recipient.`,
              "h:Reply-To": `${fromUserPrivateData.email}`
            };

          return mailgun
            .messages()
            .send(mailOptions)
            .then(() =>
              console.log(`Member '${fromUserId}' sent message to '${toUserId}'`)
            );
        }
      )
      .catch(error => console.log("Error sending message:", error));
  });
});



/**
 * Creates a Firebase account with the given user profile and returns a custom auth token allowing
 * signing-in this account.
 * Also saves the accessToken to the datastore at /linkedInAccessToken/$uid
 *
 * @returns {Promise<string>} The Firebase custom auth token in a promise.
 */
function createFirebaseAccount(email, uid, displayName, firstName, lastName, photoURL) {
  // Save the access token to the Firebase Realtime Database.
  // Taking out now, if add back replace in Promises at end
  //const databaseTask = admin.database().ref(`/linkedInAccessToken/${uid}`).set(accessToken);

  console.log('Create or update the user account in admin database', email, uid, displayName, firstName, lastName, photoURL);
  return admin.auth().updateUser(uid, {
      displayName: displayName,
      email: email,
      emailVerified: true
    })
    .catch(error => {
      // If user does not exists we create it.
      console.log(error);
      if (error.code === "auth/user-not-found") {
        console.log("Attempting to create a new account for: ", email);
        // Create user account
        return admin.auth().createUser({
            uid: uid,
            displayName: displayName,
            photoURL: photoURL,
            email: email,
            emailVerified: true
          })
          .catch(function(error) {
            console.log("Error in createUserTask: ", error);
          });
      } // END IF
      throw error;
    }) // END Catch
      .then(() => {
        const token = admin.auth().createCustomToken(uid);
        console.log('Create or update member profile in fb database', email, uid, displayName, firstName, lastName, photoURL);
        return Promise.all([token, checkUser(email, uid, displayName, firstName, lastName, photoURL)]).then(
          () => {
            console.log('Firebase custom auth token.');
            console.log(token);
            return token;
          }
        );
      });
}

// Sends a welcome email to the given user.
function sendWelcomeEmail(email, displayName) {
  const mailOptions = {
    from: `Global NL <connect@globalnl.com>`,
    to: `connect@globalnl.com`,
    subject: `GlobalNL New Member Signup`
  };

  mailOptions.text = displayName + " (" + email + ") has signed up at members.globalnl.com";

  return mailgun
    .messages()
    .send(mailOptions)
    .then(() => {
      return console.log("New member signup email notification sent to GlobalNL: " + displayName + " (" + email + ")");
    });
}

// Randomizes default member view
exports.dbSet = functions.pubsub.schedule('11 * * * *')
  .timeZone('America/New_York') // Users can choose timezone - default is America/Los_Angeles
  .onRun((context) => {
    console.log('Testing function');
    let count = 0; //counts number of members that are iterated through (not really used, can probably remove)
    let batchNum = 0; // used to index batches in the batch array
    let promiseArray = []; // needed for the promise.all
    let alpha = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]; // all letters
    let date = new Date(); // creates new date object
    let currentHour = date.getHours(); // returns the hour from the date (from 0 to 23)
    let startLetter = alpha[currentHour]; // uses current hour as an index to get the start letter
    let endLetter = alpha[currentHour + 1]; // gets end letter in same way
    if (currentHour == 23) { // condition to account for end letters that would get missed as 23 hours won't hit all letters
      endLetter = 'Z'; // at hour 23, startletter=W and endletter=Z to hit all letters in a day
    } // there aren't too many entries at those letters so it works without limit issues

    // gets users from database with last names between the two letters, limited to 500 users (no issues there yet anyway)
    let randUpdate = db.collection("members")
      .orderBy("last_name")
      .startAt(startLetter)
      .endAt(endLetter)
      .limit(500).get()
      .then(snapshot => {
        console.log("Returned " + snapshot._size + " member records between " + startLetter + " and " + endLetter);
        // used to set limit for number of users for a single batch
        let limit = 50;
        // Get a new write batch
        let batch = [];
        batch[0] = db.batch();
        snapshot.forEach(doc => {
          count = count + 1;
          // condition to reset the limit and batch when the limit is hit
          if (limit == 0) {
            // commits the batch and pushes it to the promise array
            promiseArray.push(batch[batchNum].commit().then(function() {
              console.log("Database update complete for batch # " + (batchNum + 1) + " (mid)");
            }));
            batchNum = batchNum + 1; // increases the batch number to be used as an index for the batch array
            batch[batchNum] = db.batch(); // starts a new batch in the next position of the batch array
            limit = 50; // resets the limit
          }
          // adds the random update to the batch
          batch[batchNum].update(db.collection("members").doc(doc.id), {
            random: Math.ceil(Math.random(1000) * 1000) // the random number is set with some math functions
          });
          limit = limit - 1; // decrease the limit after the batch update is created
        });
        // commits the last batch and pushes it to the promise array after all users have been interated through
        promiseArray.push(batch[batchNum].commit().then(function() {
          console.log("Database update complete for batch # " + (batchNum + 1) + " (end)");
        }));
      })
      // catches and logs any errors
      .catch(err => {
        console.log('Error getting documents ', err);
      });
    // returns a promise to ensure the function is completed
    return Promise.all(promiseArray).then(() => {
      console.log("Completing function for records between " + startLetter + " and " + endLetter);
    });
});

//Creating a '/login' api route that will handle adding Google/Apple accounts
app.post('/login', (req, res) => {
  const token = req.body.token;
  admin.auth().verifyIdToken(token)
    .then((decodedToken) => {
      const uid = decodedToken.uid;
      const email = decodedToken.email;
      const displayName = decodedToken.name || '';
      const nameArray = displayName.split(' ');
      const firstName = nameArray[0] || '';
      const lastName = nameArray[1] || '';
      const photoURL = decodedToken.picture || '';
      console.log('decoded token: ', email, uid, displayName, firstName, lastName, photoURL);
      return checkUser(email, uid, displayName, firstName, lastName, photoURL);
    })
    .then(()=>{res.send('success')})
    .catch(error => {
      console.log(error);
    });
});

app.get(
  "/auth/linkedin",
  passport.authenticate("linkedin", { state: crypto.randomBytes(20).toString("hex") })
);

app.get(
  "/auth/linkedin/callback",
  passport.authenticate("linkedin", {
    //successRedirect: `${functions.config().project.base_url}/linkedin-test`,
    failureRedirect: `${functions.config().project.base_url}/index.html`,
    session: false
  }),
  function(req, res){
    console.log('/auth/linkedin/callback');
    //console.log(req.user);
    let emailAddress = 'connect@globalnl.com';
    if(req.user.emails && req.user.emails[0] && req.user.emails[0]['value']){
      emailAddress = req.user.emails[0] && req.user.emails[0]['value'];
    }
    var photoURL = 'https://members.globalnl.com/assets/ghost_person_200x200_v1.png';
    if(req.user.photos && req.user.photos[2] && req.user.photos[2]['value']){
      photoURL = req.user.photos[0] && req.user.photos[0]['value'];
    }
    else if(req.user.photos && req.user.photos[0] && req.user.photos[0]['value']){
      photoURL = req.user.photos[0] && req.user.photos[0]['value'];
    }
    const displayName = req.user.displayName || '';
    const nameArray = displayName.split(' ');
    const firstName = nameArray[0] || '';
    const lastName = nameArray[1] || '';
    //createFirebaseAccount(email, uid, displayName, firstName, lastName, photoURL)
    return createFirebaseAccount(emailAddress, "00LI_" + req.user.id, displayName, firstName, lastName, photoURL)
    .then((firebaseToken)=>{
      return res.redirect(`${functions.config().project.base_url}/login.html?token=${firebaseToken}`);
    });
});

app.get("/linkedin-test", (req, res) => {
  if (req.user) {
    const name = req.user.name.givenName;
    const family = req.user.name.familyName;
    const photo = req.user.photos[0].value;
    const email = req.user.emails[0].value;
    console.log('/linkedin-test');
    //console.log(req.user);
    res.send(
      `<center style="font-size:140%"> <p>User is Logged In </p>
      <p>Name: ${name} ${family} </p>
      <p> Linkedn Email: ${email} </p>
      <img src="${photo}"/>
      </center>
      `
    )
  } else {
    res.send(`<center style="font-size:160%"> <p> Home Page </p>
    <p>User is not Logged In</p>
    <img style="cursor:pointer;"  onclick="window.location='/auth/linkedin'" src="https://members.globalnl.com/assets/Sign-In-Small---Hover.png"/>
    </center>
    `);
  }
});

// function that checks if a user exists in the database
function checkUser(email, uid, displayName, firstName, lastName, photoURL) {

  return db.collection("private_data").where('email', '==', email).get()
    .then((querySnapshot) => {
      if (querySnapshot.docs.length > 0) {

        console.log('email ' + email + ' found in member database updating database uid ' + querySnapshot.docs[0].id + ' (even though logged in uid is ' + uid + ')');
        
        return db.collection("members").doc(querySnapshot.docs[0].id).set({
          display_name: displayName,
          first_name: firstName,
          last_name: lastName,
          photoURL: photoURL,
          status: false,
        }, {merge: true});

      } else if (querySnapshot.docs.length <= 0) {

        console.log('email ' + email + ' not found in member database adding uid ' + uid);

        const privateDatabaseTask = db.collection("private_data").doc(uid).set({
          email: email,
          status: false,
        }, {merge: true});
        
        const memberDatabaseTask = db.collection("members").doc(uid).set({
          display_name: displayName,
          first_name: firstName,
          last_name: lastName,
          photoURL: photoURL,
          status: false,
        }, {merge: true});
      }
      return Promise.all([memberDatabaseTask, privateDatabaseTask])
    })
    .catch(error => {
      console.log(error)
    })
}

// Export the express app as an HTTP Cloud Function
exports.app = functions.https.onRequest(app);