import PushNotifications from "@pusher/push-notifications-server";

// Create beams client (backend SDK)
const beamsClient = new PushNotifications({
  instanceId: "e7c78238-d563-465f-ba04-ef4d1157e744", // your Beams instanceId
  secretKey: process.env.BEAMS_SECRET
});

export default beamsClient;
