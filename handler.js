'use strict';

const AWS = require('aws-sdk');
const cryptoRandomString = require('crypto-random-string');
const moment = require('moment');
const sgMail = require('@sendgrid/mail');
const uuid = require('uuid');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const dynamoDb = new AWS.DynamoDB.DocumentClient();

module.exports.create = (event, context, callback) => {
  const timestamp = new Date().getTime();
  // AuthCode TTL currently hardcoded to 30 minutes
  const ttl = moment(timestamp)
    .add(30, 'minutes')
    .valueOf();

  const { siteId, userId, companyEmail, companyName, userEmail } = event.queryStringParameters;

  // TODO: Add better error handling
  // Ensure all required parameters are present and sent as strings
  if (
    typeof siteId !== 'string' ||
    typeof userId !== 'string' ||
    typeof companyEmail !== 'string' ||
    typeof companyName !== 'string' ||
    typeof userEmail !== 'string'
  ) {
    callback(null, {
      statusCode: 400,
      headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
      body: 'Query param(s) either missing or improperly formatted!',
    });
    return;
  }

  // Filter existing items for ones that match the current user/site ids and have an unexpired TTL
  const scanParams = {
    TableName: process.env.DYNAMODB_TABLE,
    FilterExpression: '#sid = :sidValue and #uid = :uidValue and #ttl > :now',
    ExpressionAttributeNames: {
      '#sid': 'siteId',
      '#uid': 'userId',
      '#ttl': 'ttl',
    },
    ExpressionAttributeValues: {
      ':sidValue': siteId,
      ':uidValue': userId,
      ':now': timestamp,
    },
  };

  dynamoDb.scan(scanParams, (error, result) => {
    // Handle potential errors
    if (error) {
      callback(null, {
        statusCode: error.statusCode || 500,
        headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
        body: `Error: ${JSON.stringify(error)}`,
      });
      return;
    }

    let authCode = null;
    // If there is an existing authCode then resend it instead of generating a new one
    if (result.Items.length > 0) {
      authCode = result.Items[0].authCode;
    } else {
      // Generate a new authCode
      authCode = cryptoRandomString({ length: 6, characters: '1234567890' });
      const putParams = {
        TableName: process.env.DYNAMODB_TABLE,
        Item: {
          id: uuid.v1(),
          authCode,
          siteId,
          userId,
          ttl,
          createdAt: timestamp,
          updatedAt: timestamp,
        },
      };

      dynamoDb.put(putParams, err => {
        // Handle potential errors
        if (err) {
          callback(null, {
            statusCode: err.statusCode || 501,
            headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
            body: `Couldn't create the auth item! Error: ${JSON.stringify(err)}`,
          });
          return;
        }
      });
    }

    const msg = {
      to: `${userEmail}`,
      from: `${companyEmail}`,
      subject: `Authorization Code from ${companyName}`,
      text: `Here is your Authorization Code ${authCode} from ${companyName}.`,
      html: `<div>Authorization Code <strong>${authCode}</strong> from ${companyName}.</div>`,
    };
    sgMail.send(msg);

    callback(null, {
      statusCode: 200,
      headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
      body: 'Email sent with AuthCode!',
    });
    return;
  });
};

module.exports.verify = (event, context, callback) => {
  const timestamp = new Date().getTime();
  const { siteId, userId, authCode } = event.queryStringParameters;

  if (typeof siteId !== 'string' || typeof userId !== 'string' || typeof authCode !== 'string') {
    callback(null, {
      statusCode: 400,
      headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
      body: 'Query param(s) either missing or improperly formatted!',
    });
    return;
  }

  const params = {
    TableName: process.env.DYNAMODB_TABLE,
    FilterExpression: '#sid = :sidValue and #uid = :uidValue and authCode = :code and #ttl > :now',
    ExpressionAttributeNames: {
      '#sid': 'siteId',
      '#uid': 'userId',
      '#ttl': 'ttl',
    },
    ExpressionAttributeValues: {
      ':sidValue': siteId,
      ':uidValue': userId,
      ':code': authCode,
      ':now': timestamp,
    },
  };

  dynamoDb.scan(params, (error, result) => {
    // Handle potential errors
    if (error) {
      callback(null, {
        statusCode: error.statusCode || 501,
        headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
        body: `Error: ${JSON.stringify(error)}`,
      });
      return;
    }

    let response = {};

    // Create a response
    if (result.Items.length === 1) {
      response = {
        statusCode: 200,
        headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
        body: 'Your AuthCode has been verified!',
      };
    } else {
      response = {
        statusCode: 400,
        headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
        body: 'Your AuthCode is invalid!',
      };
    }

    callback(null, response);
  });
};
