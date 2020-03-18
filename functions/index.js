// // Create and Deploy Your First Cloud Functions
// // https://firebase.google.com/docs/functions/write-firebase-functions


/******************************************************************/
//   L I N K S
//  https://www.npmjs.com/package/pdfkit
//  http://pdfkit.org/docs/guide.pdf
//  file:///C:/Users/sandr/Downloads/coupon.pdf
//  http://masteringionic.com/blog/2017-12-22-generating-pdf-documents-with-node-and-ionic/

/******************************************************************/
/*interface Initiative {
    index: Number;
    titel: String;
    archiviert: Boolean;
    subtitel: String;
    text: String;
    text2: String; 
    picture: String;
    unterschriften: String;
    link:String;
    linkExt: String;
    shareURL: String;
    urltext: String;
}*/

/* FIREBASE */
const functions = require('firebase-functions');
const admin = require('firebase-admin');
const request = require('request');
const crypto = require('crypto');

/* OIDC */
const jwt = require('jsonwebtoken');
const WebSocket = require('ws')

//https://eid.sh.ch/.well-known/openid-configuration -> SH Production
const {
    configuration
} = require('./oidc/openid-configuration');

/* Buffer stuff */
global.Buffer = global.Buffer || require('buffer').Buffer;
if (typeof btoa === 'undefined') {
    global.btoa = function (str) {
        return new Buffer(str, 'binary').toString('base64');
    };
}

/*** ISSUER ***/
const {
    Issuer
} = require('openid-client');
const eidIssuer = new Issuer({
    issuer: configuration.Issuer,
    authorization_endpoint: configuration.authorization_endpoint,
    token_endpoint: configuration.token_endpoint,
    userinfo_endpoint: configuration.userinfo_endpoint,
    jwks_uri: configuration.jwks_uri
}); // => Issuer

/*** CLIENT ***/
const client = new eidIssuer.Client({
    client_id: functions.config().oidc.user,
    client_secret: functions.config().oidc.pwd
}); // => Client /////, [keystore]


let scope = 'openid birth_date picture verified_simple';

// // Create and Deploy Your First Cloud Functions
// // https://firebase.google.com/docs/functions/write-firebase-functions


admin.initializeApp(functions.config().firebase);

/******************************************************************/
//   E I D  /  O I D C  -  S T U F F
/******************************************************************/
exports.geteIDAuthorizationURL = functions.https.onRequest((req, res) => {

    res.set('Access-Control-Allow-Origin', '*');

    if (req.method === 'OPTIONS') {
        // Send response to OPTIONS requests
        res.set('Access-Control-Allow-Methods', 'GET');
        res.set('Access-Control-Allow-Headers', 'Content-Type');
        res.set('Access-Control-Max-Age', '3600');
        return res.status(204).send('');
    } else {

        let redirect_uri = "";
        if (req.query && req.query.web && JSON.parse(req.query.web)) { // if web
            redirect_uri = configuration.redirect_uri_web_prod;
            //redirect_uri = configuration.redirect_uri_web_dev;
        } else {
            redirect_uri = configuration.redirect_uri_mobile_prod; // NATIVE
        }

        if (req.query && req.query.claims) {
            scope = req.query.claims.replace(",", " ") + " openid verified_simple";
        }

        let authorizationUrl = client.authorizationUrl({
            //state: token,
            redirect_uri: redirect_uri,
            scope: scope, //
            //scope: 'openid profile email phone address verified_simple',
        });

        const token = crypto.randomBytes(64).toString('hex');
        //do it better https://stackoverflow.com/questions/33246028/save-token-in-local-storage-using-node      


        if (req.query && req.query.web && JSON.parse(req.query.web)) { // web

            res.status(200);
            return res.json({
                url: authorizationUrl,
                token: token
            });

        } else {

            //NATIVE

            //wss://eid.sh.ch/api/browser/?scope=openid,profile,address,verified_simple&client_id=ecollectsh&is_invite=0
            let wssurl = 'wss://eid.sh.ch/api/browser/?scope=' + scope.replace(/ /g, ',') + '&client_id=' + functions.config().oidc.user + '&is_invite=0';
            //console.log(wssurl);

            const connection = new WebSocket(wssurl)

            connection.onopen = () => {
                connection.send('Message From Client')
            }

            connection.onerror = (error) => {
                console.log(`WebSocket error: ${error}`)
            }

            connection.onmessage = (e) => {
                let message = JSON.parse(e.data);
                if (message.type === "interaction:response") {

                    //console.log(e.data);

                    // received data:  {"type": "interaction:response", "data": {"interaction_id": "4b617cc2-a3eb-4644-a52c-2481b2dff20e", "interaction_type": "share", "interaction_nonce": "dcfc72e0-6745-412e-83f9-950946a8aea1"}}

                    // now build link
                    //authorize%3Fclient_id%3Decollectsh%26scope%3Dopenid%2520profile%2520address%2520verified_simple%26response_type%3Dcode%26redirect_uri%3Decollectapp%253A%252F%252Freturn"
                    //authorize%253Fclient_id%253Decollectsh%2526scope%253Dopenid%252520profile%252520address%252520verified_simple%2526response_type%253Dcode%2526redirect_uri%253Decollectapp%25253A%25252F%25252Freturn"
                    //        https://eid.sh.ch/en/eidplus://did:eidplus:undefined/share?endpoint=wss%3A%2F%2Feid.sh.ch%2Fapi%2Fdevice%2F   4b617cc2-a3eb-4644-a52c-2481b2dff20e%2F&nonce=  dcfc72e0-6745-412e-83f9-950946a8aea1&return=https%3A%2F%2Feid.sh.ch%2Fen%2Finteraction%3Fnext%3D%2F authorize%253Fclient_id%253Decollectsh%2526scope%253Dopenid%252520profile%252520address%252520verified_simple%2526response_type%253Dcode%2526redirect_uri%253Dhttps%25253A%25252F%25252Fapp.ecollect.sh%25252Freturn
                    let url = 'eidplus://did:eidplus:undefined/share?endpoint=wss%3A%2F%2Feid.sh.ch%2Fapi%2Fdevice%2F' + message.data.interaction_id + '%2F&nonce=' + message.data.interaction_nonce + '&return=https%3A%2F%2Feid.sh.ch%2Fen%2Finteraction%3Fnext%3D%2F' + encodeURIComponent(encodeURIComponent(authorizationUrl.split('https://eid.sh.ch/')[1]));
                    //https://eid.sh.ch/en/
                    //console.log(url);


                    connection.close();
                    res.status(200);
                    return res.json({
                        //app: url,
                        url: url,
                        token: token
                    });
                }

            }

        }
    }
});


exports.geteIDData = functions.https.onRequest((req, res) => {

    res.set('Access-Control-Allow-Origin', '*');

    if (req.method === 'OPTIONS') {
        // Send response to OPTIONS requests
        res.set('Access-Control-Allow-Methods', 'POST');
        res.set('Access-Control-Allow-Headers', 'Content-Type');
        res.set('Access-Control-Max-Age', '3600');
        return res.status(204).send('');
    } else {

        // GET DATA FROM POST
        let authCode = req.body.authorization_code;
        let token = req.body.token;
        let isWeb = req.body.isWeb;
        let claims = req.body.claims;

        //console.log("GET DATA FROM POST: " + JSON.stringify(req.body));

        //TODO check Token mit auth Code
        if (!token) {
            res.status(500);
            return res.send('nice one.. ');
        }

        //return url
        var redirect_uri = configuration.redirect_uri_mobile_prod;
        if (isWeb) {
            redirect_uri = configuration.redirect_uri_web_prod;
        }

        //GET eID+ Data From Gateway
        /*console.log("Url:" + configuration.token_endpoint);
        console.log("authCode: " + authCode);
        console.log("redirect_uri: " + redirect_uri);
        console.log("functions.config().oidc.user: " + functions.config().oidc.user);
        console.log("functions.config().oidc.pwd: " + functions.config().oidc.pwd);
        */

        /**************************************************
         * GET ACCESS TOKEN via Auth Code
         */
        request.post({
                url: configuration.token_endpoint,
                form: {
                    code: authCode,
                    grant_type: "authorization_code",
                    redirect_uri: redirect_uri
                },
                headers: {
                    'Authorization': 'Basic ' + btoa(functions.config().oidc.user + ":" + functions.config().oidc.pwd)
                }
            },
            (err, httpResponse, body) => {
                if (err) {
                    console.error(err);
                    res.status(500);
                    res.send("error token endpoint " + err);
                    res.end();
                }

                let _body = JSON.parse(body);

                /**************************************************
                 * GET USER DATA
                 *************************************************/
                request({
                    method: "GET",
                    headers: {
                        "Authorization": "Bearer " + _body.access_token
                    },
                    url: configuration.userinfo_endpoint
                }, (error, response, userDataBody) => {

                    //console.log(response);
                    console.log("userDataBody " + JSON.stringify(userDataBody));
                    userDataBody = JSON.parse(userDataBody);

                    if (error) {
                        console.error(error);
                        res.status(500);
                        res.send("error user_info " + error);
                        res.end();
                    }

                    let returnData = {}

                    // if claims provided, sort out others...
                    if (claims && claims.length > 0) {
                        claims.forEach(element => {
                            returnData[element] = userDataBody[element];
                        });
                    }

                    //Verification
                    if (userDataBody && userDataBody.hasOwnProperty("verified_simple")) {
                        returnData.verified_simple = userDataBody.verified_simple;
                    }

                    res.status(200);
                    return res.json(returnData || {});

                });
            });
    }
})


exports.geteIDDataAge = functions.https.onRequest((req, res) => {

    res.set('Access-Control-Allow-Origin', '*');

    if (req.method === 'OPTIONS') {
        // Send response to OPTIONS requests
        res.set('Access-Control-Allow-Methods', 'POST');
        res.set('Access-Control-Allow-Headers', 'Content-Type');
        res.set('Access-Control-Max-Age', '3600');
        return res.status(204).send('');
    } else {

        // GET DATA FROM POST
        let authCode = req.body.authorization_code;
        let token = req.body.token;
        let isWeb = req.body.isWeb;
        let claims = ["birth_date", "picture"] // FIX 

        //console.log("GET DATA FROM POST: " + JSON.stringify(req.body));

        //TODO check Token mit auth Code
        if (!token) {
            res.status(500);
            return res.send('nice one.. ');
        }

        //return url
        var redirect_uri = configuration.redirect_uri_mobile_prod;
        if (isWeb) {
            redirect_uri = configuration.redirect_uri_web_prod;
        }

        //GET eID+ Data From Gateway
        /*console.log("Url:" + configuration.token_endpoint);
        console.log("authCode: " + authCode);
        console.log("redirect_uri: " + redirect_uri);
        console.log("functions.config().oidc.user: " + functions.config().oidc.user);
        console.log("functions.config().oidc.pwd: " + functions.config().oidc.pwd);
        */

        /**************************************************
         * GET ACCESS TOKEN via Auth Code
         */
        request.post({
                url: configuration.token_endpoint,
                form: {
                    code: authCode,
                    grant_type: "authorization_code",
                    redirect_uri: redirect_uri
                },
                headers: {
                    'Authorization': 'Basic ' + btoa(functions.config().oidc.user + ":" + functions.config().oidc.pwd)
                }
            },
            (err, httpResponse, body) => {
                if (err) {
                    console.error(err);
                    res.status(500);
                    res.send("error token endpoint " + err);
                    res.end();
                }

                let _body = JSON.parse(body);

                /**************************************************
                 * GET USER DATA
                 *************************************************/
                request({
                    method: "GET",
                    headers: {
                        "Authorization": "Bearer " + _body.access_token
                    },
                    url: configuration.userinfo_endpoint
                }, (error, response, userDataBody) => {

                    //console.log(response);
                    console.log("userDataBody " + JSON.stringify(userDataBody));
                    userDataBody = JSON.parse(userDataBody);

                    if (error) {
                        console.error(error);
                        res.status(500);
                        res.send("error user_info " + error);
                        res.end();
                    }

                    let returnData = {}

                    // Geburtsdatum verifiziert?
                    if (userDataBody.verified_simple.birth_date) {

                        let birthDate = new Date(userDataBody.birth_date.split(".")[1] + "," + userDataBody.birth_date.split(".")[0] + "," + userDataBody.birth_date.split(".")[2]);

                        console.log(birthDate);

                        //https://codereview.stackexchange.com/questions/118272/is-date-18-years-old
                        // new Date(userDataBody.birth_date.split(".")[2]+18, userDataBody.birth_date.split(".")[1]-1, userDataBody.birth_date.split(".")[1]) <= new Date();

                        let birthDate18 = new Date(Number(userDataBody.birth_date.split(".")[2]) + 18, userDataBody.birth_date.split(".")[1] - 1, userDataBody.birth_date.split(".")[1]);
                        let birthDate16 = new Date(Number(userDataBody.birth_date.split(".")[2]) + 16, userDataBody.birth_date.split(".")[1] - 1, userDataBody.birth_date.split(".")[1]);

                        console.log("18i " + birthDate18);
                        console.log("16i " + birthDate16);

                        returnData.is18 = birthDate18 <= new Date();
                        returnData.is16 = birthDate16 <= new Date();
                    } else {
                        returnData.is18 = false;
                        returnData.is16 = false;
                    }

                    //verified_simple
                    if (userDataBody && userDataBody.hasOwnProperty("verified_simple")) {
                        returnData.verified_simple = userDataBody.verified_simple;
                    }

                    console.log("Claims " + JSON.stringify(claims));
                    console.log("returnData " + JSON.stringify(returnData));
                    //console.log("userDataBody " + JSON.stringify(userDataBody));

                    res.status(200);
                    return res.json(returnData || {});

                });

            });
    }
})