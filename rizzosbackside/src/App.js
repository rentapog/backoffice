
import ClaudeChat from './components/ClaudeChat';

function App() {
  return (
    <div className="App" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#f3f4f6' }}>
      <ClaudeChat
        domain="userdomain.com"
        referralLink="https://yourapp.com/referral/USERID"
        stripeLink="https://yourstripe.com/onboarding"
      />
    </div>
  );
}

export default App;
