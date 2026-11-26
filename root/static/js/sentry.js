import * as Sentry from "@sentry/browser";

import { fetchUserProfile } from "#js/user-profile.js";

function readMetaContent(name) {
  return document.querySelector(`meta[name="${name}"]`)?.content;
}

const client = Sentry.init({
  dsn: readMetaContent("sentry-dsn"),
  environment: readMetaContent("sentry-environment"),
  release: readMetaContent("sentry-release") || undefined,
  beforeSend(event) {
    delete event.user;
    return event;
  },
  dataCollection: {
    userInfo: false,
    cookies: false,
    urlQueryParams: false,
  },
  integrations: [
    Sentry.feedbackIntegration({
      autoInject: false,
      triggerLabel: "Feedback",
      submitButtonLabel: "Send feedback",
      messagePlaceholder: "What went wrong? What did you expect?",
      useSentryUser: { email: "email", name: "name" },
    }),
  ],
});

client?.on("beforeSendFeedback", ({ contexts }) => {
  contexts.feedback.url = contexts.feedback.url?.replace(/[?#].*$/, "");
});

client?.on("beforeSendSession", (session) => {
  delete session.did;
});

fetchUserProfile().then((user) => {
  Sentry.setUser(user);
  Sentry.getFeedback()?.createWidget();
});
