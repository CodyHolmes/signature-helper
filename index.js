const crypto = require('crypto');
const qs = require('qs');

const checkSignature = (req) => {
    if(process.env.NODE_ENV === 'development'){
        return true;
    }

    const requestBody = qs.stringify(req.body, {format : 'RFC1738'});
    const signingSecret = process.env.SIGNING_SECRET;

    const timestamp = req.headers['x-sh-request-timestamp'];
    let time = Math.floor(new Date().getTime()/1000);
    if (Math.abs(time - timestamp) > 300) {
        return false;
    }

    let signatureBaseString = 'v1:' + timestamp + ':' + requestBody;

    let  = req.headers['x-sh-signature'];
    let mySignature = 'v1=' +crypto.createHmac('sha256', signingSecret).update(signatureBaseString, 'utf8').digest('hex');

    if (crypto.timingSafeEqual(
                Buffer.from(mySignature, 'utf8'),
                Buffer.from(headerSignature, 'utf8'))
        ) {
            return true;
    } else {
            return false;
    }
};

const createSignature = (body) => {
    const requestBody = qs.stringify(body, {format : 'RFC1738'});
    const signingSecret = process.env.SIGNING_SECRET;
    const timestamp = Math.floor(new Date().getTime()/1000);
    let signatureBaseString = 'v1:' + timestamp + ':' + requestBody;
    let mySignature = 'v1=' +crypto.createHmac('sha256', signingSecret).update(signatureBaseString, 'utf8').digest('hex');
    return mySignature;
};


module.exports = {
    checkSignature,
    createSignature
}