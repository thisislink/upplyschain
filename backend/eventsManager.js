const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const db = require('../database/database');

const eventsManager = async (req, res) => {
    const event = req.body;

    // Handle the event
    switch (event.type) {
        case 'checkout.session.completed':
            const session = event.data.object;
            const customerEmail = session.charge.succeeded; // Replace with the actual email field from the session object

            // Update user subscription status in the database
            const query = `UPDATE users SET is_subscribed = ? WHERE email = ?`;
            db.run(query, [true, customerEmail], function(err) {
                if (err) {
                    console.error('Error updating user subscription status:', err);
                } else {
                    console.log(`User subscription status updated for: ${customerEmail}`);
                }
            });
            break;
        // ... handle other event types
        default:
            console.log(`Unhandled event type ${event.type}`);
    }

    // Return a response to acknowledge receipt of the event
    res.json({received: true});
};

module.exports = eventsManager;
