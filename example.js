const bw_checker = require('./bw-checker');

(new bw_checker(
    null, // string if session already exists
    false, // OPTIONAL -> true if login method will enabled
    '<HOST>', // OPTIONAL
    '<ACCOUNT-EMAIL>', // OPTIONAL
    '<MASTER-PASSWORD>' // OPTIONAL
)).execute();