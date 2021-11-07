# Client

The Sancus client enables customers to interact with the institutional backend to access their accounts.


## Getting started
1. Complete the setup instructions for [Sancus](../README.md) if you haven't already
1. Activate your Python virtual environment for Sancus
1. Start the Sacnus backend if it isn't already running: `python3 -m configurations.local.local`
1. `yarn`
1. Make your changes
1. `yarn lint` and fix the errors until none appear


## Running the client
After you start the backend, navigate to [https://localhost:8443/](https://localhost:8443/). Your browser
will display a certificate error (because the local backend uses a self-signed certificate). Ignore the error
(e.g. in Chrome, click "advanced", then "Continue to localhost (unsafe)"). You will need to repeat this each time
you start the client.


Then, run `yarn start`. Then open [http://localhost:3000](http://localhost:3000) to view it in the browser.

The page will reload if you make edits. You will also see any lint errors in the console.

## Hosting on openstack
Nginx is already configured to point port 443 to the build folder. After making changes to the frontend, they can be deployed with `yarn build`. 
