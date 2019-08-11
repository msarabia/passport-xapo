/**
 * Created by msarabia on 12/7/18.
 */

let OAuth2Strategy = require('passport-oauth2');
let InternalOAuthError = OAuth2Strategy.InternalOAuthError;

module.exports = class StrategyXapo extends OAuth2Strategy {
    constructor(_options, _verify) {
        const options = _options || {};
        const verify = _verify;
        const versionApi = options.version || "v2";
        const baseURL = `https://${versionApi}.api.xapo.com`;

        options.authorizationURL = options.authorizationURL || `${baseURL}/oauth2/authorization`;
        options.tokenURL = options.tokenURL || `${baseURL}/oauth2/token`;
        options.customHeaders = {
            Authorization: 'Basic ' + Buffer.from(options.clientID + ':' + options.clientSecret).toString('base64')
        };

        if (!options.callbackURL) throw new TypeError("Is needed callbackURL settings");

        super(options, verify);

        this.name = "xapocm";
        this._profileURL = options.profileURL || `${baseURL}/users`;
        this._accountUrl = options.accountURL || `${baseURL}/accounts`;

        this._oauth2.useAuthorizationHeaderforGET(true)
    }



    userProfile(accessToken, done) {
        const profileURL = this._profileURL;
        const accountURL = this._accountUrl;

        // Get Profile
        this._oauth2.get(profileURL, accessToken, (err, bodyProfile, res) => {
            //Get Account information

            this._oauth2.get(accountURL, accessToken, (err, bodyAccount, res) => {

                    if (err) return done(new InternalOAuthError('Failed to fetch user Account', err));

                    //profile
                    let jsonProfile;
                    if (bodyProfile) {
                        jsonProfile = JSON.parse(bodyProfile)[0];
                    }
                    else {
                        jsonProfile = {
                            first_name: "",
                            last_name: "",
                            middle_name: ""
                        };
                    }
                    // account information
                    let jsonAccount;
                    try {
                        jsonAccount = JSON.parse(bodyAccount)[0]
                    } catch (e) {
                        return done(e)
                    }

                    const profile = {
                        provider: 'xapocm',
                        id: jsonProfile.id || jsonAccount.owner_id,
                        displayName: `${jsonProfile.first_name} ${jsonProfile.last_name}` || '',
                        name: {
                            familyName: jsonProfile.last_name || '',
                            givenName: jsonProfile.first_name || '',
                            middleName: jsonProfile.middle_name || '',
                        },
                        gender: jsonProfile.gender || '',
                        emails: [{
                            value: jsonProfile.primary_email || '',
                        }],
                        photos: [{
                            value: jsonProfile.avatar || '',
                        }],
                        walletId: jsonAccount.id,
                        wallet: jsonAccount.primary_address,
                        walletName: jsonAccount.name,
                        balance: jsonAccount.balance,
                        currency: jsonAccount.currency,
                        walletActive: jsonAccount.active,

                        _raw: bodyAccount,
                        _json: jsonAccount,
                    };

                    return done(null, profile)
                }
            )
        });

    }
};