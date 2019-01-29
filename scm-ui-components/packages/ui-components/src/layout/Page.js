//@flow
import * as React from "react";
import Loading from "./../Loading";
import ErrorNotification from "./../ErrorNotification";
import Title from "./Title";
import Subtitle from "./Subtitle";
import HorizontalRule from "./HorizontalRule";

type Props = {
  title?: string,
  subtitle?: string,
  loading?: boolean,
  error?: Error,
  showContentOnError?: boolean,
  horizontalRuleClass?: string,
  children: React.Node
};

class Page extends React.Component<Props> {
  render() {
    const { title, error, subtitle } = this.props;
    return (
      <section className="section">
        <div className="container">
          <Title title={title} />
          {this.renderHorizontalRule()}
          <Subtitle subtitle={subtitle} />
          <ErrorNotification error={error} />
          {this.renderContent()}
        </div>
      </section>
    );
  }

  renderHorizontalRule() {
    const { horizontalRuleClass } = this.props;
    if (horizontalRuleClass) {
      return <HorizontalRule className={horizontalRuleClass} />;
    }
  }

  renderContent() {
    const { loading, children, showContentOnError, error } = this.props;
    if (error && !showContentOnError) {
      return null;
    }
    if (loading) {
      return <Loading />;
    }
    return children;
  }
}

export default Page;
