import React, { useState, useEffect } from 'react';
import { Typography } from '@material-ui/core';

type Props = {
  expiration: Date,
  updateRate: () => void,
}

const ExpirationCountdown = (props: Props) => {
  const { expiration, updateRate } = props;
  const [timeLeft, setTimeLeft] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setTimeLeft(Math.floor((expiration.getTime() - Date.now()) / 1000));
      if (timeLeft <= 0) {
        updateRate();
      }
    }, 1000);
    return () => {
      clearTimeout(timer);
    };
  });

  return (
    <>
      <Typography>
        {`Exchange rate will update in ${timeLeft} seconds`}
      </Typography>
    </>
  );
};

export default ExpirationCountdown;
