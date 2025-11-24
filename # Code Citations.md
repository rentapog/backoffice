# Code Citations

## License: unknown
https://github.com/mcs83/drbook/tree/6fdae3dfb432bfb876079ce4d78ee319193fb2ba/src/backend/app.py

```
app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(
            payload,
```

