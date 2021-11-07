import React from 'react';
import { Box } from '@material-ui/core';

import AccountInfoBox from '../accounts/AccountInfoBox';
import { useAppSelector } from '../../app/hooks';

type AccountChooserProps = {
  selection: (bytesId: Uint8Array, currency: string, available: string) => void,
  omit: string | null,
}

const AccountChooser = (props: AccountChooserProps) => {
  const { selection, omit } = props;

  const accountsInfo = useAppSelector((state) => {
    return state.accounts.accounts;
  });

  const accountInfoBoxes = accountsInfo ? accountsInfo.map((acc) => {
    const bytesId = acc.getId_asU8();
    const id = acc.getId_asB64();
    if (acc.getCurrency() !== omit) {
      return (
        <AccountInfoBox
          id={id}
          bytesId={bytesId}
          selectAcc={selection}
          accountType={acc.getAccounttype()}
          currency={acc.getCurrency()}
          available={acc.getAvailableamount()}
          pending={acc.getPendingamount()}
          key={id}
        />
      );
    }
    return <></>;
  }) : <></>;

  return (
    <Box>
      {accountInfoBoxes}
    </Box>
  );
};

export default AccountChooser;
