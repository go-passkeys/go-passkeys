window.appLogin = function() {
    console.log("login");
}

function err(text) {
  document.getElementById("errortext").textContent = text;

  const ele = document.getElementById("error");
  ele.style.visibility = "visible";
}

function appHideError() {
  const ele = document.getElementById("error");
  ele.style.visibility = "hidden";
}
window.appHideError = appHideError;

window.appRegister = async function() {
	appHideError();
    const username = document.getElementById("register_username").value;
    if (username == "") {
		err("No username entered");
        return;
    }

    try {
        const resp = await fetch("/registration-start", {
            method: "POST",
            body: JSON.stringify({
                username: username,
            }),
        });
        if (!resp.ok) {
            err(await resp.text());
            return;
        }

        const body = await resp.json();
        const challenge = Uint8Array.from(atob(body.challenge), c => c.charCodeAt(0));
        const userID = Uint8Array.from(atob(body.userID), c => c.charCodeAt(0));

        // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
        // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
        let cred = await navigator.credentials.create({
            publicKey: {
                challenge: challenge,
                rp: {
                    id: "localhost",
                    name: "go-webauthn",
                },
                attestation: "direct",
                user: {
                    id: userID,
                    name: username,
                    displayName: username,
                },
                // https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/pub_key_cred_params.md
                // https://www.w3.org/TR/webauthn-2/#typedefdef-cosealgorithmidentifier
                pubKeyCredParams: [
                    {
                        type: "public-key",
                        alg: -7,
                    },
                    {
                        type: "public-key",
                        alg: -257,
                    },
                ],
                authenticatorSelection: {
                    requireResidentKey: true,
                    residentKey: "required",
                },
            },
        });

        const attestationObject = btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject)));
        const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)));

        const finishResp = await fetch("/registration-finish", {
            method: "POST",
            body: JSON.stringify({
                attestationObject: attestationObject,
                clientDataJSON: clientDataJSON,
            }),
        });
        if (!resp.ok) {
            err(await resp.text());
            return;
        }
		window.location.herf = "/";
		window.location.reload();
    } catch (error) {
        err(error);
    }
}

window.appLogin = async function() {
	appHideError();
    const username = document.getElementById("login_username").value;
    if (username == "") {
		err("No username entered");
        return;
    }

    try {
        const resp = await fetch("/login-start", {
            method: "POST",
            body: JSON.stringify({
                username: username,
            }),
        });
        if (!resp.ok) {
            err(await resp.text());
            return;
        }

        const body = await resp.json();
        const challenge = Uint8Array.from(atob(body.challenge), c => c.charCodeAt(0));

		const cred = await navigator.credentials.get({
           publicKey: {
			   challenge: challenge,
               rpId: "localhost",
               userVerification: "required",
		   },
		});

        const authenticatorData = btoa(String.fromCharCode(...new Uint8Array(cred.response.authenticatorData)));
        const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)));
        const signature = btoa(String.fromCharCode(...new Uint8Array(cred.response.signature)));
        const userHandle = btoa(String.fromCharCode(...new Uint8Array(cred.response.userHandle)));

        const finishResp = await fetch("/login-finish", {
            method: "POST",
            body: JSON.stringify({
				authenticatorData: authenticatorData,
				clientDataJSON: clientDataJSON,
				signature: signature,
				userHandle: userHandle,
            }),
        });
        if (!finishResp.ok) {
            err(await finishResp.text());
            return;
        }

		console.log("Logged in");

		window.location.herf = "/";
		window.location.reload();
    } catch (error) {
        err(error);
    }
}

window.appReauth = async function() {
	appHideError();
    try {
        const resp = await fetch("/reauth-start", {
            method: "POST",
            body: JSON.stringify({}),
        });
        if (!resp.ok) {
            err(await resp.text());
            return;
        }

        const body = await resp.json();
        const challenge = Uint8Array.from(atob(body.challenge), c => c.charCodeAt(0));
		const creds = body.credentialIDs.map((credID) => {
			return {
			    id: Uint8Array.from(atob(credID), c => c.charCodeAt(0)),
			};
		});
		console.log(creds);

		const cred = await navigator.credentials.get({
           publicKey: {
			   challenge: challenge,
               rpId: "localhost",
               userVerification: "required",
			   allowcredentials: creds,
		   },
		});

        const authenticatorData = btoa(String.fromCharCode(...new Uint8Array(cred.response.authenticatorData)));
        const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)));
        const signature = btoa(String.fromCharCode(...new Uint8Array(cred.response.signature)));
        const userHandle = btoa(String.fromCharCode(...new Uint8Array(cred.response.userHandle)));

        const finishResp = await fetch("/reauth-finish", {
            method: "POST",
            body: JSON.stringify({
				authenticatorData: authenticatorData,
				clientDataJSON: clientDataJSON,
				signature: signature,
				userHandle: userHandle,
            }),
        });
        if (!finishResp.ok) {
            err(await finishResp.text());
            return;
        }
		alert("Reauthenticated successfully");
    } catch (error) {
        err(error);
    }
}

window.appRegisterKey = async function() {
	appHideError();
    try {
        const resp = await fetch("/register-key-start", {
            method: "POST",
            body: JSON.stringify({}),
        });
        if (!resp.ok) {
            err(await resp.text());
            return;
        }

        const body = await resp.json();
        const challenge = Uint8Array.from(atob(body.challenge), c => c.charCodeAt(0));
        const credID = Uint8Array.from(atob(body.credentialID), c => c.charCodeAt(0));
        const userID = Uint8Array.from(atob(body.userID), c => c.charCodeAt(0));
		const creds = body.credentialIDs.map((credID) => {
			return {
				type: "public-key",
			    id: Uint8Array.from(atob(credID), c => c.charCodeAt(0)),
			};
		});

        // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
        // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
        let cred = await navigator.credentials.create({
            publicKey: {
                challenge: challenge,
				excludeCredentials: creds,
                rp: {
                    id: "localhost",
                    name: "go-webauthn",
                },
                attestation: "direct",
                user: {
                    id: userID,
                    name: body.username,
                    displayName: body.username,
                },
                // https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/pub_key_cred_params.md
                // https://www.w3.org/TR/webauthn-2/#typedefdef-cosealgorithmidentifier
                pubKeyCredParams: [
                    {
                        type: "public-key",
                        alg: -7,
                    },
                    {
                        type: "public-key",
                        alg: -257,
                    },
                ],
                authenticatorSelection: {
                    requireResidentKey: true,
                    residentKey: "required",
                },
            },
        });

        const attestationObject = btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject)));
        const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)));

        const finishResp = await fetch("/register-key-finish", {
            method: "POST",
            body: JSON.stringify({
                attestationObject: attestationObject,
                clientDataJSON: clientDataJSON,
            }),
        });
        if (!resp.ok) {
            err(await resp.text());
            return;
        }
		window.location.herf = "/";
		window.location.reload();
    } catch (error) {
        err(error);
    }
}
