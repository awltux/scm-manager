import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { addDecorator, configure } from "@storybook/react";
import { withI18next } from "storybook-addon-i18next";

import "!style-loader!css-loader!sass-loader!../../ui-styles/src/scm.scss";
import React, { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";

i18n.use(initReactI18next).init({
  whitelist: ["en", "de", "es"],
  lng: "en",
  fallbackLng: "en",
  interpolation: {
    escapeValue: false
  },
  react: {
    useSuspense: false
  }
});

addDecorator(
  withI18next({
    i18n,
    languages: {
      en: "English",
      de: "Deutsch",
      es: "Spanisch"
    }
  })
);

const RoutingDecorator = (story) => <MemoryRouter initialEntries={["/"]}>{story()}</MemoryRouter>;
addDecorator(RoutingDecorator);

configure(require.context("../src", true, /\.stories\.tsx?$/), module);
