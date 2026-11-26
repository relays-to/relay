import * as Sentry from "@sentry/browser";

const readMetaContent = (name) =>
  document.querySelector(`meta[name="${name}"]`)?.content;

Sentry.init({
  dsn: readMetaContent("sentry-dsn"),
  environment: readMetaContent("sentry-environment"),
  release: readMetaContent("sentry-release") || undefined,
  dataCollection: {
    userInfo: false,
    cookies: false,
    urlQueryParams: false,
  },
  integrations: [
    Sentry.feedbackIntegration({
      triggerLabel: "Feedback",
      submitButtonLabel: "Send feedback",
      messagePlaceholder: "What went wrong? What did you expect?",
    }),
  ],
})?.on("beforeSendFeedback", ({ contexts }) => {
  contexts.feedback.url = contexts.feedback.url?.replace(/[?#].*$/, "");
});
