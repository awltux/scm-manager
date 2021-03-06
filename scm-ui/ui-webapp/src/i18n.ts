import i18n from "i18next";
// @ts-ignore
import Backend from "i18next-fetch-backend";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";
import { urls } from "@scm-manager/ui-components";

const loadPath = urls.withContextPath("/locales/{{lng}}/{{ns}}.json");

i18n
  .use(Backend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: "en",

    // try to load only "en" and not "en_US"
    load: "languageOnly",

    // have a common namespace used around the full app
    ns: ["commons"],
    defaultNS: "commons",

    debug: false,

    interpolation: {
      escapeValue: false // not needed for react!!
    },

    react: {
      wait: true,
      useSuspense: false
    },

    backend: {
      loadPath: loadPath,
      init: {
        credentials: "same-origin"
      }
    }
  });

export default i18n;
